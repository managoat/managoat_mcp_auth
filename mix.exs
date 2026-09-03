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
      aliases: aliases(),
      description: "MCP authorization discovery with a server-side URL guard.",
      package: package(),
      source_url: @source_url,
      docs: docs(),
      dialyzer: dialyzer(),
      test_coverage: [summary: [threshold: 100]]
    ]
  end

  # `mix precommit` runs in :test so that its compile, credo and test steps see
  # exactly what CI sees — .github/workflows/ci.yml sets MIX_ENV=test for the
  # whole job. The two steps that must not run there shell out to :dev.
  def cli do
    [preferred_envs: [precommit: :test]]
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

  # The CI gate, in CI's order, in one command. Keep this and
  # .github/workflows/ci.yml in step: a check that lives only in CI is a check
  # every contributor discovers by pushing.
  defp aliases do
    [
      precommit: [
        &deps_unlock_unused_changes_nothing/1,
        "format --check-formatted",
        "compile --warnings-as-errors",
        "credo --strict",
        &dialyzer_in_dev/1,
        "test --cover",
        &hex_build_in_dev/1
      ]
    ]
  end

  # Parity with CI's `mix deps.unlock --unused && git diff --exit-code
  # mix.lock`. A bare "deps.unlock --unused" step rewrites the lockfile and
  # exits 0, so the alias would pass while CI failed the same commit on the
  # diff. Compared against the file as it was a moment ago rather than against
  # git HEAD, so an uncommitted but legitimate lockfile edit (a dependency
  # added on this branch) does not trip it.
  defp deps_unlock_unused_changes_nothing(_args) do
    before = File.read!("mix.lock")
    Mix.Task.run("deps.unlock", ["--unused"])

    if File.read!("mix.lock") != before do
      Mix.raise(
        "mix.lock listed unused dependencies (deps.unlock --unused just pruned them). " <>
          "Commit the updated mix.lock — CI fails this via `git diff --exit-code mix.lock`."
      )
    end

    :ok
  end

  # MIX_ENV=dev on purpose, the same override CI makes: dialyzer analyzes the
  # shipped code, and the test env would drag test-only dependencies into the
  # analysis and into the cached PLT. A function rather than a "cmd ..." step
  # because `mix cmd` execs without a shell and cannot set the environment.
  defp dialyzer_in_dev(_args), do: mix_in_dev(["dialyzer"])

  # What `mix hex.publish` will build, in the environment it builds it in: a
  # dependency hex refuses (a git dep, a path dep) fails here rather than on
  # the PR. The tarball goes to a temporary directory because it is a check,
  # not an artifact, and nothing here should have to gitignore it.
  defp hex_build_in_dev(_args) do
    app = Atom.to_string(Mix.Project.config()[:app])
    mix_in_dev(["hex.build", "--output", Path.join(System.tmp_dir!(), app <> "-precommit.tar")])
  end

  defp mix_in_dev(args) do
    case Mix.shell().cmd(Enum.join(["mix" | args], " "), env: [{"MIX_ENV", "dev"}]) do
      0 -> :ok
      status -> Mix.raise("mix #{Enum.join(args, " ")} failed with exit status #{status}")
    end
  end
end
