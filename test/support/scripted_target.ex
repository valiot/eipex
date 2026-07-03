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
    {:ok, agent} = Agent.start_link(fn -> %{frames: [], socket: nil} end)

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
        handle_frame(socket, frame, handler, opts)
        drain(socket, rest, handler, agent, opts)

      :partial ->
        buffer
    end
  end

  defp handle_frame(socket, %Encap{command: :register_session} = frame, _handler, _opts) do
    reply = %Encap{frame | session_handle: @session_handle}
    :gen_tcp.send(socket, Encap.encode(reply))
  end

  defp handle_frame(socket, %Encap{command: :send_rr_data} = frame, handler, opts) do
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

        send_reply(socket, Encap.encode(reply), opts)
    end
  end

  defp handle_frame(_socket, %Encap{command: :unregister_session}, _handler, _opts), do: :ok
  defp handle_frame(_socket, %Encap{command: :nop}, _handler, _opts), do: :ok

  defp send_reply(socket, binary, opts) do
    if opts[:split_replies] do
      half = div(byte_size(binary), 2)
      <<a::binary-size(half), b::binary>> = binary
      :gen_tcp.send(socket, a)
      Process.sleep(10)
      :gen_tcp.send(socket, b)
    else
      :gen_tcp.send(socket, binary)
    end
  end
end
