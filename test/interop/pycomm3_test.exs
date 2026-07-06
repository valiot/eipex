defmodule Eipex.Interop.Pycomm3Test do
  @moduledoc """
  Interop: pycomm3 (reference Python scanner) against our adapter.
  Requires docker. Run with: mix test --include interop
  """

  use ExUnit.Case

  @moduletag :interop
  @moduletag timeout: 300_000

  test "pycomm3 talks to our adapter over UCMM" do
    {:ok, _adapter} =
      Eipex.Adapter.start_link(
        identity: [
          vendor_id: 0x4D,
          device_type: 0x0C,
          product_code: 0x77,
          revision: {1, 2},
          serial_number: 0x99,
          product_name: "Eipex Adapter"
        ],
        assemblies: [output: [instance: 150, size: 4]],
        port: 44_821,
        ip: {0, 0, 0, 0},
        io_udp_port: 0
      )

    script = Path.expand("../../interop/pycomm3/check_adapter.py", __DIR__)

    {output, exit_code} =
      System.cmd(
        "docker",
        [
          "run",
          "--rm",
          "--network",
          "host",
          "-v",
          "#{script}:/check_adapter.py:ro",
          "-e",
          "ADAPTER_HOST=127.0.0.1",
          "-e",
          "ADAPTER_PORT=44821",
          "python:3.11-slim",
          "sh",
          "-c",
          "pip install --quiet pycomm3 && python /check_adapter.py"
        ],
        stderr_to_stdout: true
      )

    assert exit_code == 0, "pycomm3 run failed:\n#{output}"

    json = output |> String.split("\n", trim: true) |> List.last()
    results = JSON.decode!(json)

    assert results["vendor_ok"]
    assert results["vendor"] == [0x4D, 0x00]
    assert results["write_ok"]
    assert results["readback_ok"]
    assert results["unknown_class_errors"]
    assert results["connected_ok"]
    assert results["connected_vendor"] == [0x4D, 0x00]
  end
end
