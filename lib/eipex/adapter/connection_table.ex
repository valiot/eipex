defmodule Eipex.Adapter.ConnectionTable do
  @moduledoc """
  Registry of class 3 connections: triad -> connection info, with capacity
  enforcement and automatic cleanup when the owning TCP session dies
  (monitor-based). One per adapter.
  """

  use GenServer

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  def register(table, triad, info, session_pid),
    do: GenServer.call(table, {:register, triad, info, session_pid})

  def unregister(table, triad), do: GenServer.call(table, {:unregister, triad})

  def lookup_o2t(table, o2t_id), do: GenServer.call(table, {:lookup_o2t, o2t_id})

  def count(table), do: GenServer.call(table, :count)

  @impl true
  def init(opts) do
    {:ok,
     %{max: Keyword.fetch!(opts, :max), by_triad: %{}, by_o2t: %{}, monitors: %{}, next_id: 1}}
  end

  @impl true
  def handle_call({:register, triad, info, session_pid}, _from, state) do
    cond do
      Map.has_key?(state.by_triad, triad) ->
        {:reply, {:error, :duplicate}, state}

      map_size(state.by_triad) >= state.max ->
        {:reply, {:error, :capacity}, state}

      true ->
        o2t_id = state.next_id
        info_with_kind = Map.put_new(info, :kind, :explicit)
        record = Map.merge(info_with_kind, %{triad: triad, session: session_pid, o2t_id: o2t_id})

        monitors =
          state.monitors
          |> Map.put_new_lazy(session_pid, fn ->
            Process.monitor(session_pid)
          end)
          |> then(fn monitors ->
            if pid = info_with_kind[:pid] do
              Map.put_new_lazy(monitors, pid, fn ->
                Process.monitor(pid)
              end)
            else
              monitors
            end
          end)

        {:reply, {:ok, o2t_id},
         %{
           state
           | by_triad: Map.put(state.by_triad, triad, record),
             by_o2t: Map.put(state.by_o2t, o2t_id, record),
             monitors: monitors,
             next_id: state.next_id + 1
         }}
    end
  end

  def handle_call({:unregister, triad}, _from, state) do
    case Map.pop(state.by_triad, triad) do
      {nil, _} ->
        {:reply, {:error, :not_found}, state}

      {record, by_triad} ->
        {:reply, {:ok, record},
         %{state | by_triad: by_triad, by_o2t: Map.delete(state.by_o2t, record.o2t_id)}}
    end
  end

  def handle_call({:lookup_o2t, o2t_id}, _from, state) do
    case state.by_o2t do
      %{^o2t_id => record} -> {:reply, {:ok, record}, state}
      _ -> {:reply, :error, state}
    end
  end

  def handle_call(:count, _from, state), do: {:reply, map_size(state.by_triad), state}

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, _reason}, state) do
    {dead, by_triad} =
      Enum.split_with(state.by_triad, fn {_triad, record} ->
        record.session == pid or record[:pid] == pid
      end)

    by_o2t = Enum.reduce(dead, state.by_o2t, fn {_t, r}, acc -> Map.delete(acc, r.o2t_id) end)

    {:noreply,
     %{
       state
       | by_triad: Map.new(by_triad),
         by_o2t: by_o2t,
         monitors: Map.delete(state.monitors, pid)
     }}
  end

  def handle_info(_message, state), do: {:noreply, state}
end
