defmodule Eipex.CIP.PathTest do
  use ExUnit.Case, async: true

  alias Eipex.CIP.Path

  test "message router path: class 0x02 instance 1 (8-bit)" do
    assert Path.encode(class: 0x02, instance: 0x01) == <<0x20, 0x02, 0x24, 0x01>>
  end

  test "16-bit instance inserts a pad byte after the type byte" do
    # Symbol Object class 0x6B, instance 0xF68F (1756-PM020 example)
    assert Path.encode(class: 0x6B, instance: 0xF68F) ==
             <<0x20, 0x6B, 0x25, 0x00, 0x8F, 0xF6>>
  end

  test "even-length symbolic segment has no pad" do
    assert Path.encode(symbolic: "TotalCount") ==
             <<0x91, 0x0A, "TotalCount">>
  end

  test "odd-length symbolic segment is padded to a word boundary" do
    assert Path.encode(symbolic: "ports") == <<0x91, 0x05, "ports", 0x00>>
  end

  test "port segment routes to backplane slot" do
    assert Path.encode([{:port, 1, 0}, {:class, 0x02}, {:instance, 1}]) ==
             <<0x01, 0x00, 0x20, 0x02, 0x24, 0x01>>
  end

  test "attribute and member segments" do
    assert Path.encode(class: 0x01, instance: 1, attribute: 7) ==
             <<0x20, 0x01, 0x24, 0x01, 0x30, 0x07>>

    assert Path.encode(symbolic: "Struct.M", member: 3) ==
             <<0x91, 0x08, "Struct.M", 0x28, 0x03>>
  end

  test "words/1 counts 16-bit words" do
    assert Path.words(Path.encode(class: 0x02, instance: 1)) == 2
  end

  test "decode round-trips logical, symbolic and port segments" do
    segs = [{:port, 1, 0}, {:class, 0x6B}, {:instance, 0xF68F}, {:attribute, 2}]
    assert {:ok, ^segs} = segs |> Path.encode() |> Path.decode()

    segs2 = [{:symbolic, "ports"}, {:member, 3}]
    assert {:ok, ^segs2} = segs2 |> Path.encode() |> Path.decode()
  end

  test "decode rejects garbage without raising" do
    assert {:error, :malformed_path} = Path.decode(<<0x91, 0x09, "abc">>)
    assert {:error, :malformed_path} = Path.decode(<<0xFF, 0x00>>)
  end
end
