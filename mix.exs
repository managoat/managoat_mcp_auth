defmodule Managoat.McpAuth.MixProject do
  use Mix.Project

  @version "0.1.1"
  @source_url "https://github.com/managoat/managoat_mcp_auth"

  def project do
    [
      app: :managoat_mcp_auth,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "MCP authorization discovery with a server-side URL guard.",
      package: package(),
      source_url: @source_url,
      docs: docs(),
      dialyzer: dialyzer(),
      test_coverage: [summary: [threshold: 100]]
    ]
  end

  def application do
    [extra_applications: []]
  end

  defp deps do
    [
      # Tooling for the repository, not the package: docs for hexdocs.pm (built
      # by `mix hex.publish`), credo and dialyzer for CI. dialyxir is pinned to
      # the commit that added OTP 28 support; 1.4.7 crashes on OTP 28 warnings.
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir,
       github: "jeremyjh/dialyxir",
       ref: "3553678f4d69281ac6db61034bcf35bcb30cfd78",
       only: [:dev, :test],
       runtime: false},
      {:req, "~> 0.5"},
      {:jason, "~> 1.2"},
      # Req keeps Plug optional; Req.Test's concurrent HTTP stubs need it only
      # while this library's tests run. It is not a package runtime dependency.
      {:plug, "~> 1.0", only: :test}
    ]
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url, "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md"},
      files: ~w(lib mix.exs README.md CHANGELOG.md LICENSE NOTICE)
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "CHANGELOG.md"],
      source_ref: "v#{@version}",
      source_url: @source_url
    ]
  end

  defp dialyzer do
    [
      ignore_warnings: ".dialyzer_ignore.exs",
      # A fixed path so CI can cache the PLT across runs.
      plt_file: {:no_warn, "priv/plts/dialyzer.plt"}
    ]
  end
end
