defmodule Eipex.Adapter.IoLoopbackTest do
  use ExUnit.Case

  alias Eipex.{CPF, Encap, Scanner}
  alias Eipex.CIP.ConnectionManager, as: CM
  alias Eipex.CIP.MessageRouter, as: MR
  alias Eipex.CIP.Path

  defmodule IoHandler do
    use Eipex.Adapter.Handler

    def after_assembly_write(instance, data, _ctx) do
      send(:io_loopback_test, {:written, instance, data})
      :ok
    end

    def run_idle_changed(_info, mode) do
      send(:io_loopback_test, {:run_idle, mode})
      :ok
    end

    def connection_event(_info, event) do
      send(:io_loopback_test, {:conn_event, event})
      :ok
    end
  end

  @identity [
    vendor_id: 0x4D,
    device_type: 0x0C,
    product_code: 0x77,
    revision: {1, 2},
    serial_number: 0x99,
    product_name: "Eipex Adapter"
  ]

  setup do
    Process.register(self(), :io_loopback_test)

    {:ok, adapter} =
      Eipex.Adapter.start_link(
        identity: @identity,
        handler: IoHandler,
        assemblies: [
          input: [instance: 100, size: 4],
          output: [instance: 150, size: 4],
          config: [instance: 151, size: 2]
        ],
        port: 0,
        io_udp_port: 0,
        io: [multicast: [group: {239, 192, 77, 1}, interface: {127, 0, 0, 1}, ttl: 1]]
      )

    {:ok, tcp_port} = Eipex.Adapter.port(adapter)
    {:ok, io_port} = Eipex.Adapter.io_udp_port(adapter)

    socket = connect(tcp_port)
    handle = register(socket)

    {:ok, udp} = :gen_udp.open(0, [:binary, active: true])
    {:ok, my_udp_port} = :inet.port(udp)

    on_exit(fn ->
      if Process.whereis(:io_loopback_test), do: Process.unregister(:io_loopback_test)
    end)

    %{
      adapter: adapter,
      socket: socket,
      handle: handle,
      udp: udp,
      my_udp_port: my_udp_port,
      io_port: io_port
    }
  end

  defp connect(port) do
    {:ok, socket} =
      :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, packet: :raw, active: false])

    socket
  end

  defp send_frame(socket, frame), do: :ok = :gen_tcp.send(socket, Encap.encode(frame))

  defp recv_frame(socket, buffer \\ <<>>) do
    {:ok, data} = :gen_tcp.recv(socket, 0, 1_000)

    case Encap.decode(buffer <> data) do
      {:ok, frame, _rest} -> frame
      :partial -> recv_frame(socket, buffer <> data)
    end
  end

  defp register(socket) do
    send_frame(socket, Encap.register_session())
    %Encap{session_handle: handle} = recv_frame(socket)
    handle
  end

  defp io_forward_open(ctx, overrides \\ []) do
    # 4 data + 2 seq + 4 run/idle
    o2t_size = Keyword.get(overrides, :o2t_size, 10)
    # 4 data + 2 seq
    t2o_size = Keyword.get(overrides, :t2o_size, 6)
    rpi = Keyword.get(overrides, :rpi, 20_000)
    serial = Keyword.get(overrides, :serial, 1)
    conn_type = Keyword.get(overrides, :conn_type, :point_to_point)

    path =
      Keyword.get(
        overrides,
        :path,
        Path.encode([
          {:class, 0x04},
          {:instance, 151},
          {:connection_point, 150},
          {:connection_point, 100}
        ])
      )

    fo = %CM.ForwardOpen{
      priority_time_tick: 0x0A,
      timeout_ticks: 10,
      o2t_connection_id: 0,
      t2o_connection_id: 0x5150_0000 + serial,
      connection_serial: serial,
      originator_vendor_id: 0x004D,
      originator_serial: 0xDEAD_0001,
      timeout_multiplier: Keyword.get(overrides, :multiplier, 1),
      o2t_rpi: rpi,
      o2t_params: %{
        owner: :exclusive,
        type: conn_type,
        priority: :low,
        size_type: :fixed,
        size: o2t_size
      },
      t2o_rpi: rpi,
      t2o_params: %{
        owner: :exclusive,
        type: Keyword.get(overrides, :t2o_conn_type, conn_type),
        priority: :low,
        size_type: :fixed,
        size: t2o_size
      },
      transport: %{direction: :server, trigger: :cyclic, class: 1},
      connection_path: path
    }

    cpf =
      CPF.encode([
        :null_address,
        {:unconnected_data, CM.encode_forward_open(fo, :standard)},
        {:sockaddr_t2o, %{ip: {0, 0, 0, 0}, port: ctx.my_udp_port}}
      ])

    send_frame(ctx.socket, Encap.send_rr_data(ctx.handle, cpf))
    reply = recv_frame(ctx.socket)
    {:ok, rcpf} = Encap.unwrap_cpf(reply)
    {:ok, items} = CPF.decode(rcpf)
    [{:unconnected_data, mr}] = for {:unconnected_data, _} = i <- items, do: i
    {:ok, response} = MR.decode_response(mr)
    sockaddrs = for {tag, _} = i <- items, tag in [:sockaddr_o2t, :sockaddr_t2o], do: i

    fo_reply =
      if response.status_name == :success do
        {:ok, reply} = CM.decode_forward_open_reply(response.data)
        reply
      end

    {fo, response, fo_reply, sockaddrs}
  end

  # Same class 1 Forward Open as `io_forward_open/2`, but wrapped in an
  # Unconnected Send (service 0x52 to class 0x06 instance 1) — how a routed
  # Rockwell/pycomm3 scanner actually sends a class 1 FO. The sockaddr_t2o
  # item travels in the OUTER CPF (Unconnected Send has no CPF of its own);
  # the adapter must thread it through the re-dispatch to the embedded FO.
  defp io_forward_open_via_unconnected_send(ctx, overrides \\ []) do
    o2t_size = Keyword.get(overrides, :o2t_size, 10)
    t2o_size = Keyword.get(overrides, :t2o_size, 6)
    rpi = Keyword.get(overrides, :rpi, 20_000)
    serial = Keyword.get(overrides, :serial, 1)

    path =
      Path.encode([
        {:class, 0x04},
        {:instance, 151},
        {:connection_point, 150},
        {:connection_point, 100}
      ])

    fo = %CM.ForwardOpen{
      priority_time_tick: 0x0A,
      timeout_ticks: 10,
      o2t_connection_id: 0,
      t2o_connection_id: 0x5255_0000 + serial,
      connection_serial: serial,
      originator_vendor_id: 0x004D,
      originator_serial: 0xDEAD_0002,
      timeout_multiplier: Keyword.get(overrides, :multiplier, 1),
      o2t_rpi: rpi,
      o2t_params: %{
        owner: :exclusive,
        type: :point_to_point,
        priority: :low,
        size_type: :fixed,
        size: o2t_size
      },
      t2o_rpi: rpi,
      t2o_params: %{
        owner: :exclusive,
        type: :point_to_point,
        priority: :low,
        size_type: :fixed,
        size: t2o_size
      },
      transport: %{direction: :server, trigger: :cyclic, class: 1},
      connection_path: path
    }

    embedded = CM.encode_forward_open(fo, :standard)
    unconnected_send = CM.encode_unconnected_send(embedded, [{:port, 1, 0}], [])

    cpf =
      CPF.encode([
        :null_address,
        {:unconnected_data, unconnected_send},
        {:sockaddr_t2o, %{ip: {0, 0, 0, 0}, port: ctx.my_udp_port}}
      ])

    send_frame(ctx.socket, Encap.send_rr_data(ctx.handle, cpf))
    reply = recv_frame(ctx.socket)
    {:ok, rcpf} = Encap.unwrap_cpf(reply)
    {:ok, items} = CPF.decode(rcpf)
    [{:unconnected_data, mr}] = for {:unconnected_data, _} = i <- items, do: i
    {:ok, response} = MR.decode_response(mr)
    sockaddrs = for {tag, _} = i <- items, tag in [:sockaddr_o2t, :sockaddr_t2o], do: i

    fo_reply =
      if response.status_name == :success do
        {:ok, reply} = CM.decode_forward_open_reply(response.data)
        reply
      end

    {fo, response, fo_reply, sockaddrs}
  end

  defp forward_close(ctx, fo) do
    triad = %{
      connection_serial: fo.connection_serial,
      originator_vendor_id: fo.originator_vendor_id,
      originator_serial: fo.originator_serial
    }

    cpf =
      CPF.encode([
        :null_address,
        {:unconnected_data, CM.encode_forward_close(triad, fo.connection_path, [])}
      ])

    send_frame(ctx.socket, Encap.send_rr_data(ctx.handle, cpf))
    reply = recv_frame(ctx.socket)
    {:ok, rcpf} = Encap.unwrap_cpf(reply)
    {:ok, items} = CPF.decode(rcpf)
    [{:unconnected_data, mr}] = for {:unconnected_data, _} = i <- items, do: i
    MR.decode_response(mr)
  end

  defp send_o2t(ctx, conn_id, seq, run, data) do
    packet = Eipex.IO.encode_packet(conn_id, seq, seq, run, data)
    :ok = :gen_udp.send(ctx.udp, {127, 0, 0, 1}, ctx.io_port, packet)
  end

  defp flush_udp do
    receive do
      {:udp, _, _, _, _} -> flush_udp()
    after
      0 -> :ok
    end
  end

  test "forward open succeeds, adapter produces on the RPI", ctx do
    {fo, response, fo_reply, [{:sockaddr_o2t, %{port: adapter_io_port}}]} = io_forward_open(ctx)
    assert response.status_name == :success
    assert adapter_io_port == ctx.io_port
    assert_receive {:conn_event, :opened}, 500
    assert fo_reply.t2o_connection_id == fo.t2o_connection_id

    # production arrives on our UDP socket: t2o id, growing sequences, zeroed data
    assert_receive {:udp, _, _, _, datagram}, 500

    assert {:ok, %{conn_id: conn_id, data: <<0, 0, 0, 0>>, run: nil, seq32: s1}} =
             Eipex.IO.decode_packet(datagram, false)

    assert conn_id == fo.t2o_connection_id

    assert_receive {:udp, _, _, _, datagram2}, 500
    {:ok, %{seq32: s2}} = Eipex.IO.decode_packet(datagram2, false)
    assert Eipex.IO.seq_newer?(s2, s1)

    # refresh the produced data through the public API
    :ok = Eipex.Adapter.write_assembly(ctx.adapter, 100, <<9, 8, 7, 6>>)
    assert_eventually_produces(<<9, 8, 7, 6>>)
  end

  test "consumption writes the output assembly and reports run/idle", ctx do
    {_fo, response, fo_reply, _sockaddrs} = io_forward_open(ctx)
    assert response.status_name == :success

    send_o2t(ctx, fo_reply.o2t_connection_id, 1, :run, <<1, 2, 3, 4>>)

    assert_receive {:written, 150, <<1, 2, 3, 4>>}
    assert_receive {:run_idle, :run}
    assert Eipex.Adapter.read_assembly(ctx.adapter, 150) == {:ok, <<1, 2, 3, 4>>}
  end

  test "stale sequences are dropped", ctx do
    # generous multiplier: this test isn't exercising the watchdog and must
    # not race against it during the refute_receive gap below.
    {_fo, response, fo_reply, _sockaddrs} = io_forward_open(ctx, multiplier: 7)
    assert response.status_name == :success

    send_o2t(ctx, fo_reply.o2t_connection_id, 5, :run, <<1, 1, 1, 1>>)
    assert_receive {:written, 150, <<1, 1, 1, 1>>}

    send_o2t(ctx, fo_reply.o2t_connection_id, 3, :run, <<2, 2, 2, 2>>)
    refute_receive {:written, 150, <<2, 2, 2, 2>>}, 200
    assert Eipex.Adapter.read_assembly(ctx.adapter, 150) == {:ok, <<1, 1, 1, 1>>}

    send_o2t(ctx, fo_reply.o2t_connection_id, 6, :run, <<3, 3, 3, 3>>)
    assert_receive {:written, 150, <<3, 3, 3, 3>>}
  end

  test "run to idle transition fires exactly once each", ctx do
    {_fo, response, fo_reply, _sockaddrs} = io_forward_open(ctx)
    assert response.status_name == :success

    send_o2t(ctx, fo_reply.o2t_connection_id, 7, :run, <<1, 2, 3, 4>>)
    assert_receive {:run_idle, :run}

    send_o2t(ctx, fo_reply.o2t_connection_id, 8, :idle, <<1, 2, 3, 4>>)
    assert_receive {:run_idle, :idle}
  end

  test "watchdog closes an idle connection and frees the triad", ctx do
    {fo, response, fo_reply, _sockaddrs} = io_forward_open(ctx, rpi: 20_000, multiplier: 0)
    assert response.status_name == :success

    send_o2t(ctx, fo_reply.o2t_connection_id, 1, :run, <<1, 2, 3, 4>>)
    assert_receive {:written, 150, <<1, 2, 3, 4>>}

    assert_receive {:conn_event, :timeout}, 1_000

    flush_udp()
    refute_receive {:udp, _, _, _, _}, 200

    {_fo2, response2, _fo_reply2, _sa2} = io_forward_open(ctx, serial: fo.connection_serial)
    assert response2.status_name == :success
  end

  test "forward close stops production", ctx do
    {fo, response, _fo_reply, _sockaddrs} = io_forward_open(ctx)
    assert response.status_name == :success
    assert_receive {:conn_event, :opened}, 500

    assert {:ok, %{status_name: :success}} = forward_close(ctx, fo)
    assert_receive {:conn_event, :closed}, 500

    flush_udp()
    refute_receive {:udp, _, _, _, _}, 200
  end

  test "size mismatch answers 0x0127/0x0128 with the correct size", ctx do
    {_fo, response, _fo_reply, _sockaddrs} = io_forward_open(ctx, o2t_size: 99, serial: 1)
    assert response.extended == [0x0127, 10]

    {_fo2, response2, _fo_reply2, _sa2} = io_forward_open(ctx, t2o_size: 99, serial: 2)
    assert response2.extended == [0x0128, 6]
  end

  test "o2t multicast is refused", ctx do
    {_fo, response, _fo_reply, _sockaddrs} = io_forward_open(ctx, conn_type: :multicast)
    assert response.extended == [0x0123]
  end

  test "t2o multicast forward open returns the group and produces to it", ctx do
    {fo, response, fo_reply, sockaddrs} = io_forward_open(ctx, t2o_conn_type: :multicast)
    assert response.status_name == :success

    # the target assigns the T->O connection id of a multicast producer
    refute fo_reply.t2o_connection_id == fo.t2o_connection_id

    # the reply announces the group and port where production goes
    assert [%{ip: {239, 192, 77, 1} = group, port: group_port}] =
             for({:sockaddr_t2o, sa} <- sockaddrs, do: sa)

    # join the group like a consumer would; production must land there,
    # stamped with the adapter-assigned connection id
    {:ok, member} =
      :gen_udp.open(group_port, [
        :binary,
        active: true,
        reuseaddr: true,
        add_membership: {group, {127, 0, 0, 1}}
      ])

    assert_receive {:udp, ^member, _ip, _port, datagram}, 500

    assert {:ok, %{conn_id: conn_id, data: <<0, 0, 0, 0>>}} =
             Eipex.IO.decode_packet(datagram, false)

    assert conn_id == fo_reply.t2o_connection_id
    :gen_udp.close(member)
  end

  test "path and kind validation", ctx do
    swapped_path =
      Path.encode([
        {:class, 4},
        {:instance, 151},
        {:connection_point, 100},
        {:connection_point, 150}
      ])

    {_fo, response, _fo_reply, _sockaddrs} =
      io_forward_open(ctx, path: swapped_path, serial: 1)

    assert response.extended == [0x012A]

    {_fo2, response2, _fo_reply2, _sa2} = io_forward_open(ctx, rpi: 100, serial: 2)
    assert response2.extended == [0x0111]
  end

  test "a class 1 forward open wrapped in unconnected send resolves the real peer", ctx do
    {fo, response, fo_reply, sockaddrs} = io_forward_open_via_unconnected_send(ctx)

    assert response.status_name == :success
    assert fo_reply.t2o_connection_id == fo.t2o_connection_id

    # the embedded FO's sockaddr_o2t reply item must propagate through the
    # Unconnected Send re-dispatch to the outer encapsulation reply
    assert [{:sockaddr_o2t, %{port: adapter_io_port}}] = sockaddrs
    assert adapter_io_port == ctx.io_port

    # T->O production must land on the test's real UDP endpoint, not on a
    # localhost:2222 fallback caused by a dropped peer_ip/cpf_items
    assert_receive {:udp, _, _, _, datagram}, 1_000
    assert {:ok, %{conn_id: conn_id}} = Eipex.IO.decode_packet(datagram, false)
    assert conn_id == fo.t2o_connection_id
  end

  test "exclusive-owner conflict: a second FO to the same o2t assembly is refused", ctx do
    {_fo, response, _fo_reply, _sockaddrs} = io_forward_open(ctx)
    assert response.status_name == :success

    {_fo2, response2, _fo_reply2, _sa2} = io_forward_open(ctx, serial: 2)
    assert response2.extended == [0x0106]
  end

  defp assert_eventually_produces(expected, tries \\ 20) do
    assert tries > 0, "never produced #{inspect(expected)}"

    receive do
      {:udp, _, _, _, datagram} ->
        case Eipex.IO.decode_packet(datagram, false) do
          {:ok, %{data: ^expected}} -> :ok
          _ -> assert_eventually_produces(expected, tries - 1)
        end
    after
      500 -> flunk("no production within 500ms")
    end
  end

  describe "scanner loopback matrix" do
    test "run/idle transition reaches the adapter handler" do
      {_adapter, scanner} = start_scanner_pair()
      assert {:ok, io} = open_scanner_io(scanner)

      # the scanner always produces Run when o2t run_idle is configured, so
      # the adapter's handler must see the idle -> run transition exactly once
      assert_receive {:run_idle, :run}, 1_000
      refute_receive {:run_idle, :run}, 200

      Scanner.IOConnection.close(io)
      Scanner.close(scanner)
    end

    test "adapter watchdog fires when the scanner's io connection dies" do
      {_adapter, scanner} = start_scanner_pair()
      assert {:ok, io} = open_scanner_io(scanner)

      assert_receive {:conn_event, :opened}, 1_000

      # io is linked to this test process (Scanner.open_io/2 calls start_link
      # from the caller); trap exits so the :killed signal doesn't tear us down
      old_trap = Process.flag(:trap_exit, true)
      Process.exit(io, :kill)

      receive do
        {:EXIT, ^io, :killed} -> :ok
      after
        100 -> :ok
      end

      # no more O->T traffic reaches the adapter: its own watchdog fires and
      # frees the triad (observed here via a fresh open_io succeeding again)
      assert_receive {:conn_event, :timeout}, 1_000
      Process.flag(:trap_exit, old_trap)

      assert {:ok, io2} = open_scanner_io(scanner)
      assert_receive {:eipex_io, ^io2, :data, _}, 1_000

      Scanner.IOConnection.close(io2)
      Scanner.close(scanner)
    end

    test "scanner watchdog fires when the adapter's io connection dies" do
      {adapter, scanner} = start_scanner_pair()
      assert {:ok, io} = open_scanner_io(scanner)
      # monitor before triggering the kill: io notifies :timeout and then
      # stops in the same callback, so monitoring only after the notification
      # would race the process's own exit (Process.monitor/1 on an already
      # -dead pid reports :noproc instead of the real reason)
      io_ref = Process.monitor(io)

      assert_receive {:eipex_io, ^io, :data, _}, 1_000

      [{_, io_statem, _, _}] =
        DynamicSupervisor.which_children(Eipex.Adapter.config(adapter).io.sup)

      ref = Process.monitor(io_statem)
      Process.exit(io_statem, :kill)
      assert_receive {:DOWN, ^ref, :process, ^io_statem, :killed}, 1_000

      # no more T->O traffic reaches the scanner: its watchdog fires, notifies
      # the owner and the io connection stops (normal exit, no crash)
      assert_receive {:eipex_io, ^io, :timeout}, 1_000
      assert_receive {:DOWN, ^io_ref, :process, ^io, :normal}, 1_000

      Scanner.close(scanner)
    end

    test "two quick set_output calls land in order; the last one wins" do
      {adapter, scanner} = start_scanner_pair()
      assert {:ok, io} = open_scanner_io(scanner)

      assert_receive {:eipex_io, ^io, :data, _}, 1_000

      :ok = Scanner.IOConnection.set_output(io, <<1, 1, 1, 1>>)
      :ok = Scanner.IOConnection.set_output(io, <<2, 2, 2, 2>>)

      assert eventually(fn ->
               Eipex.Adapter.read_assembly(adapter, 150) == {:ok, <<2, 2, 2, 2>>}
             end)

      Scanner.IOConnection.close(io)
      Scanner.close(scanner)
    end

    test "capacity applies to io connections" do
      {_adapter, scanner} = start_scanner_pair(max_connections: 1)

      assert {:ok, io} = open_scanner_io(scanner)

      # a different o2t assembly than `io`'s, so this probes capacity
      # (0x0113) rather than tripping the exclusive-owner conflict (0x0106)
      assert {:error, {:cip, :connection_failure, [0x0113]}} =
               open_scanner_io(scanner,
                 o_to_t: [assembly: 152, size: 4, rpi: 20_000, run_idle: true]
               )

      Scanner.IOConnection.close(io)
      Scanner.close(scanner)
    end

    test "closing an io connection frees capacity for the next one" do
      {_adapter, scanner} = start_scanner_pair(max_connections: 1)

      assert {:ok, io} = open_scanner_io(scanner)

      assert {:error, {:cip, :connection_failure, [0x0113]}} =
               open_scanner_io(scanner,
                 o_to_t: [assembly: 152, size: 4, rpi: 20_000, run_idle: true]
               )

      assert :ok = Scanner.IOConnection.close(io)

      assert {:ok, io2} = open_scanner_io(scanner)
      assert_receive {:eipex_io, ^io2, :data, _}, 1_000

      Scanner.IOConnection.close(io2)
      Scanner.close(scanner)
    end
  end

  defp start_scanner_pair(adapter_extra \\ []) do
    {:ok, adapter} =
      Eipex.Adapter.start_link(
        [
          identity: @identity,
          handler: IoHandler,
          assemblies: [
            input: [instance: 100, size: 4],
            output: [instance: 150, size: 4],
            # a second, distinct consuming assembly so capacity tests can
            # probe capacity (0x0113) without tripping the exclusive-owner
            # conflict check (0x0106) on the same o2t assembly
            output: [instance: 152, size: 4],
            config: [instance: 151, size: 2]
          ],
          port: 0,
          io_udp_port: 0
        ] ++ adapter_extra
      )

    {:ok, port} = Eipex.Adapter.port(adapter)

    {:ok, scanner} =
      Scanner.start_link(
        host: {127, 0, 0, 1},
        port: port,
        vendor_id: 0x004D,
        serial_number: 0xDEAD_0001
      )

    {adapter, scanner}
  end

  defp open_scanner_io(scanner, extra \\ []) do
    Scanner.open_io(
      scanner,
      [
        o_to_t: [assembly: 150, size: 4, rpi: 20_000, run_idle: true],
        t_to_o: [assembly: 100, size: 4, rpi: 20_000, run_idle: false],
        config: [assembly: 151],
        timeout_multiplier: 0,
        owner: self()
      ] ++ extra
    )
  end

  defp eventually(fun, tries \\ 50) do
    cond do
      fun.() -> true
      tries == 0 -> false
      true -> Process.sleep(20) && eventually(fun, tries - 1)
    end
  end
end
