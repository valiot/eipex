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

  test "io records carry kind and pid, and die with the pid" do
    {:ok, table} = ConnectionTable.start_link(max: 8)

    statem =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    triad = {9, 0x004D, 0xDEAD_0009}

    assert {:ok, o2t} =
             ConnectionTable.register(
               table,
               triad,
               %{t2o_connection_id: 42, kind: :io, pid: statem},
               self()
             )

    assert {:ok, %{kind: :io, pid: ^statem}} = ConnectionTable.lookup_o2t(table, o2t)

    send(statem, :stop)
    Process.sleep(50)
    assert :error = ConnectionTable.lookup_o2t(table, o2t)
  end

  test "explicit records default kind" do
    {:ok, table} = ConnectionTable.start_link(max: 8)

    {:ok, o2t} =
      ConnectionTable.register(table, {1, 1, 1}, %{t2o_connection_id: 1}, self())

    assert {:ok, %{kind: :explicit}} = ConnectionTable.lookup_o2t(table, o2t)
  end

  test "o2t ids are random, unique and nonzero" do
    {:ok, table} = ConnectionTable.start_link(max: 8)

    {:ok, o2t1} = ConnectionTable.register(table, {1, 1, 1}, %{t2o_connection_id: 1}, self())
    {:ok, o2t2} = ConnectionTable.register(table, {2, 1, 1}, %{t2o_connection_id: 2}, self())

    assert o2t1 != 0
    assert o2t2 != 0
    assert o2t1 != o2t2
  end

  test "io_owns_assembly? reflects registered io records" do
    {:ok, table} = ConnectionTable.start_link(max: 8)

    refute ConnectionTable.io_owns_assembly?(table, 150)

    {:ok, _o2t} =
      ConnectionTable.register(
        table,
        {1, 1, 1},
        %{t2o_connection_id: 1, kind: :io, pid: self(), o2t_assembly: 150},
        self()
      )

    assert ConnectionTable.io_owns_assembly?(table, 150)
    refute ConnectionTable.io_owns_assembly?(table, 151)
  end
end
