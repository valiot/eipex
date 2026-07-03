defmodule Eipex.EncapTest do
  use ExUnit.Case, async: true

  alias Eipex.Encap

  # RegisterSession request: command 0x65, length 4, session 0, status 0,
  # zeroed context/options, data = protocol version 1 + flags 0.
  @register_session_frame <<0x65, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0x01, 0x00, 0x00, 0x00>>

  test "encodes a RegisterSession frame" do
    frame = %Encap{command: :register_session, data: <<1::16-little, 0::16-little>>}
    assert Encap.encode(frame) == @register_session_frame
  end

  test "decodes a RegisterSession frame" do
    assert {:ok,
            %Encap{
              command: :register_session,
              session_handle: 0,
              status: 0,
              data: <<1::16-little, 0::16-little>>
            },
            <<>>} =
             Encap.decode(@register_session_frame)
  end

  test "decode keeps trailing bytes as rest (TCP stream reassembly)" do
    assert {:ok, %Encap{command: :register_session}, <<0xAB>>} =
             Encap.decode(@register_session_frame <> <<0xAB>>)
  end

  test "decode returns :partial for incomplete header or body" do
    assert :partial = Encap.decode(binary_part(@register_session_frame, 0, 10))
    assert :partial = Encap.decode(binary_part(@register_session_frame, 0, 26))
  end

  test "decode rejects unknown commands without raising" do
    bogus = <<0xFF, 0xFF, 0::16, 0::32, 0::32, 0::64, 0::32>>
    assert {:error, {:unknown_command, 0xFFFF}} = Encap.decode(bogus)
  end

  test "round-trips every command" do
    for cmd <- [
          :nop,
          :list_services,
          :list_identity,
          :list_interfaces,
          :register_session,
          :unregister_session,
          :send_rr_data,
          :send_unit_data
        ] do
      frame = %Encap{command: cmd, session_handle: 0x11223344, data: <<1, 2, 3>>}
      assert {:ok, ^frame, <<>>} = frame |> Encap.encode() |> Encap.decode()
    end
  end

  test "status_name maps encapsulation status codes" do
    assert Encap.status_name(0x0000) == :success
    assert Encap.status_name(0x0001) == :invalid_command
    assert Encap.status_name(0x0002) == :insufficient_memory
    assert Encap.status_name(0x0003) == :incorrect_data
    assert Encap.status_name(0x0064) == :invalid_session_handle
    assert Encap.status_name(0x0065) == :invalid_length
    assert Encap.status_name(0x0069) == :unsupported_protocol_version
    assert Encap.status_name(0x1234) == :unknown
  end

  describe "command builders" do
    test "register_session carries protocol version 1" do
      assert %Encap{command: :register_session, session_handle: 0, data: <<1, 0, 0, 0>>} =
               Encap.register_session()
    end

    test "unregister_session carries the session handle, no data" do
      assert %Encap{command: :unregister_session, session_handle: 0xCAFE, data: <<>>} =
               Encap.unregister_session(0xCAFE)
    end

    test "list_identity is sessionless and empty" do
      assert %Encap{command: :list_identity, session_handle: 0, data: <<>>} =
               Encap.list_identity()
    end

    test "send_rr_data prefixes interface handle 0 and timeout" do
      cpf = <<0xDE, 0xAD>>
      frame = Encap.send_rr_data(0x1234, cpf, 10)
      assert frame.command == :send_rr_data
      assert frame.session_handle == 0x1234
      assert frame.data == <<0::32-little, 10::16-little, 0xDE, 0xAD>>
    end

    test "send_unit_data uses timeout 0" do
      frame = Encap.send_unit_data(0x1234, <<0xBE, 0xEF>>)
      assert frame.data == <<0::32-little, 0::16-little, 0xBE, 0xEF>>
    end

    test "unwrap_cpf strips the 6-byte interface prefix" do
      frame = Encap.send_rr_data(1, <<1, 2, 3>>)
      assert {:ok, <<1, 2, 3>>} = Encap.unwrap_cpf(frame)

      assert {:error, :bad_interface_data} =
               Encap.unwrap_cpf(%Encap{command: :send_rr_data, data: <<1>>})
    end
  end
end
