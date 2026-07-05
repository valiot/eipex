defmodule Eipex.Adapter.ConnectionTableTest do
  use ExUnit.Case, async: true

  alias Eipex.Adapter.ConnectionTable

  @triad {1, 0x004D, 0xDEAD_0001}

  test "registers, looks up and unregisters connections" do
    {:ok, table} = ConnectionTable.start_link(max: 8)

    assert {:ok, o2t} = ConnectionTable.register(table, @triad, %{t2o_connection_id: 7}, self())
    assert o2t != 0
    assert ConnectionTable.count(table) == 1

    assert {:ok, %{triad: @triad, t2o_connection_id: 7, session: session}} =
             ConnectionTable.lookup_o2t(table, o2t)

    assert session == self()

    assert {:ok, _info} = ConnectionTable.unregister(table, @triad)
    assert :error = ConnectionTable.lookup_o2t(table, o2t)
    assert {:error, :not_found} = ConnectionTable.unregister(table, @triad)
  end

  test "rejects duplicate triads and enforces capacity" do
    {:ok, table} = ConnectionTable.start_link(max: 1)

    assert {:ok, _} = ConnectionTable.register(table, @triad, %{t2o_connection_id: 1}, self())

    assert {:error, :duplicate} =
             ConnectionTable.register(table, @triad, %{t2o_connection_id: 2}, self())

    other = {2, 0x004D, 0xDEAD_0001}

    assert {:error, :capacity} =
             ConnectionTable.register(table, other, %{t2o_connection_id: 3}, self())
  end

  test "a dead session releases its connections" do
    {:ok, table} = ConnectionTable.start_link(max: 8)

    session =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    {:ok, o2t} = ConnectionTable.register(table, @triad, %{t2o_connection_id: 1}, session)
    send(session, :stop)
    Process.sleep(50)

    assert :error = ConnectionTable.lookup_o2t(table, o2t)
    assert ConnectionTable.count(table) == 0
    # triad reusable after cleanup
    assert {:ok, _} = ConnectionTable.register(table, @triad, %{t2o_connection_id: 2}, self())
  end
end
