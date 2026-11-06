defmodule Eipex.MixProject do
  use Mix.Project

  @version "0.2.0"
  @source_url "https://github.com/valiot/eipex"

  def project do
    [
      app: :eipex,
      version: @version,
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env()),
      name: "Eipex",
      description: description(),
      package: package(),
      docs: docs(),
      source_url: @source_url
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp description do
    "A pure-Elixir EtherNet/IP (CIP) protocol stack: scanner (originator) and " <>
      "adapter (target) roles, explicit and implicit (class 1 I/O) messaging, " <>
      "and Rockwell Logix tag services."
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      maintainers: ["Valiot"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md"
      },
      files: ~w(lib priv .formatter.exs mix.exs README.md CHANGELOG.md LICENSE)
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "CHANGELOG.md"],
      source_ref: "v#{@version}",
      groups_for_modules: [
        Codecs: [
          Eipex.Encap,
          Eipex.CPF,
          Eipex.Identity,
          Eipex.IO,
          Eipex.CIP.Path,
          Eipex.CIP.MessageRouter,
          Eipex.CIP.Types,
          Eipex.CIP.ConnectionManager,
          Eipex.CIP.Logix
        ],
        Scanner: [
          Eipex.Scanner,
          Eipex.Scanner.Discovery,
          Eipex.Scanner.IOConnection,
          Eipex.Scanner.Logix,
          Eipex.Scanner.Logix.Value,
          Eipex.Tag
        ],
        Adapter: [
          Eipex.Adapter,
          Eipex.Adapter.Config,
          Eipex.Adapter.Handler,
          Eipex.Adapter.Object,
          Eipex.Adapter.AssemblyStore,
          Eipex.Adapter.ConnectionTable
        ]
      ]
    ]
  end

  defp deps do
    [
      {:stream_data, "~> 1.1", only: [:dev, :test]},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end
