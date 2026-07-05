defmodule Eipex.TestSupport.ScriptedTarget do
  @moduledoc """
  A minimal EtherNet/IP target for tests: a real TCP listener on loopback,
  driven by the real Eipex codecs. Answers RegisterSession automatically;
  every SendRRData is passed (as the raw Message Router request binary) to
  the handler fun, whose binary return is wrapped and sent back with the
  same sender context. No mocks: the scanner under test talks real bytes.
  """

  alias Eipex.{CPF, Encap}

  @session_handle 0x1234

  def start(handler, opts \\ []) do
    parent = self()
    {:ok, listen} = :gen_tcp.listen(0, [:binary, packet: :raw, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(listen)
    {:ok, agent} = Agent.start_link(fn -> %{frames: [], socket: nil, prefix_sent: false} end)

    pid =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listen)
        Agent.update(agent, &%{&1 | socket: socket})
        send(parent, {:scripted_target_connected, self()})
        serve(socket, <<>>, handler, agent, opts)
      end)

    %{port: port, pid: pid, agent: agent, listen: listen}
  end

  @doc "All frames received so far, oldest first."
  def frames(%{agent: agent}) do
    agent |> Agent.get(& &1.frames) |> Enum.reverse()
  end

  @doc "Close the connection from the target side."
  def close(%{agent: agent}) do
    case Agent.get(agent, & &1.socket) do
      nil -> :ok
      socket -> :gen_tcp.close(socket)
    end
  end

  defp serve(socket, buffer, handler, agent, opts) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, data} ->
        buffer = drain(socket, buffer <> data, handler, agent, opts)
        serve(socket, buffer, handler, agent, opts)

      {:error, _} ->
        :ok
    end
  end

  defp drain(socket, buffer, handler, agent, opts) do
    case Encap.decode(buffer) do
      {:ok, frame, rest} ->
        Agent.update(agent, fn s -> %{s | frames: [frame | s.frames]} end)
        handle_frame(socket, frame, handler, agent, opts)
        drain(socket, rest, handler, agent, opts)

      :partial ->
        buffer
    end
  end

  defp handle_frame(socket, %Encap{command: :register_session} = frame, _handler, _agent, opts) do
    reply = %Encap{frame | session_handle: @session_handle}
    :gen_tcp.send(socket, Encap.encode(reply) <> (opts[:register_trailer] || <<>>))
  end

  defp handle_frame(socket, %Encap{command: :send_rr_data} = frame, handler, agent, opts) do
    if opts[:rst_after_reply] do
      # hold the reply briefly so a concurrent caller has a real window to
      # queue a second request behind this one before the reset lands
      Process.sleep(30)
    end

    {:ok, cpf} = Encap.unwrap_cpf(frame)
    {:ok, items} = CPF.decode(cpf)
    [{:unconnected_data, mr_request}] = for {:unconnected_data, _} = i <- items, do: i

    case handler.(mr_request) do
      :no_reply ->
        :ok

      mr_response when is_binary(mr_response) ->
        reply_cpf = CPF.encode([:null_address, {:unconnected_data, mr_response}])

        reply = %Encap{
          Encap.send_rr_data(@session_handle, reply_cpf)
          | sender_context: frame.sender_context
        }

        send_reply(socket, Encap.encode(reply), opts, agent)
    end
  end

  defp handle_frame(socket, %Encap{command: :send_unit_data} = frame, _handler, agent, opts) do
    case opts[:unit_handler] do
      nil ->
        :ok

      unit_handler ->
        {:ok, cpf} = Encap.unwrap_cpf(frame)
        {:ok, items} = CPF.decode(cpf)
        [{:connected_address, conn_id}] = for {:connected_address, _} = i <- items, do: i

        [{:connected_data, <<seq::16-little, mr::binary>>}] =
          for {:connected_data, _} = i <- items, do: i

        case unit_handler.(conn_id, seq, mr) do
          :no_reply ->
            :ok

          {reply_conn_id, response} ->
            reply_cpf =
              CPF.encode([
                {:connected_address, reply_conn_id},
                {:connected_data, <<seq::16-little, response::binary>>}
              ])

            reply = %Encap{
              Encap.send_unit_data(@session_handle, reply_cpf)
              | sender_context: frame.sender_context
            }

            send_reply(socket, Encap.encode(reply), opts, agent)
        end
    end
  end

  defp handle_frame(_socket, %Encap{command: :unregister_session}, _handler, _agent, _opts),
    do: :ok

  defp handle_frame(_socket, %Encap{command: :nop}, _handler, _agent, _opts), do: :ok

  defp send_reply(socket, binary, opts, agent) do
    case opts[:reply_prefix] do
      nil ->
        :ok

      prefix ->
        already_sent =
          Agent.get_and_update(agent, fn s -> {s.prefix_sent, %{s | prefix_sent: true}} end)

        unless already_sent do
          :gen_tcp.send(socket, prefix)
          Process.sleep(5)
        end
    end

    if opts[:split_replies] do
      half = div(byte_size(binary), 2)
      <<a::binary-size(half), b::binary>> = binary
      :gen_tcp.send(socket, a)
      Process.sleep(10)
      :gen_tcp.send(socket, b)
    else
      :gen_tcp.send(socket, binary)
    end

    if opts[:rst_after_reply] do
      :inet.setopts(socket, [{:linger, {true, 0}}])
      :gen_tcp.close(socket)
    end
  end
end
