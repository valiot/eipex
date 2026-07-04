defmodule Eipex.Scanner.Discovery do
  @moduledoc """
  EtherNet/IP device discovery: ListIdentity over UDP (broadcast or unicast).
  Every device on the segment answers with its Identity item.
  """

  alias Eipex.{CPF, Encap}
  alias Eipex.Identity

  @default_address {255, 255, 255, 255}
  @default_port 44_818
  @default_timeout 1_000

  @spec discover(keyword()) :: {:ok, [Identity.t()]} | {:error, term()}
  def discover(opts \\ []) do
    address = Keyword.get(opts, :address, @default_address)
    port = Keyword.get(opts, :port, @default_port)
    timeout = Keyword.get(opts, :timeout, @default_timeout)

    with {:ok, socket} <- :gen_udp.open(0, [:binary, active: false, broadcast: true]),
         :ok <- :gen_udp.send(socket, address, port, Encap.encode(Encap.list_identity())) do
      deadline = System.monotonic_time(:millisecond) + timeout
      identities = collect(socket, deadline, [])
      :gen_udp.close(socket)
      {:ok, identities}
    end
  end

  defp collect(socket, deadline, acc) do
    remaining = deadline - System.monotonic_time(:millisecond)

    if remaining <= 0 do
      Enum.reverse(acc)
    else
      case :gen_udp.recv(socket, 0, remaining) do
        {:ok, {_ip, _port, data}} -> collect(socket, deadline, parse(data) ++ acc)
        {:error, _} -> Enum.reverse(acc)
      end
    end
  end

  defp parse(data) do
    with {:ok, %Encap{command: :list_identity, status: 0, data: cpf}, _rest} <-
           Encap.decode(data),
         {:ok, items} <- CPF.decode(cpf) do
      for {:identity, identity} <- items, do: identity
    else
      _ -> []
    end
  end
end
