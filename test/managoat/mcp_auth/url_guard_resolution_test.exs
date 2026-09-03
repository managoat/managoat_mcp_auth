defmodule Managoat.McpAuth.UrlGuardResolutionTest do
  # The Erlang resolver table is VM-global, so these tests must not overlap the
  # async URL syntax tests. Unique RFC-reserved names keep the test offline.
  use ExUnit.Case

  alias Managoat.McpAuth.UrlGuard

  @private_addresses [
    {0, 1, 2, 3},
    {10, 1, 2, 3},
    {127, 1, 2, 3},
    {169, 254, 2, 3},
    {172, 16, 2, 3},
    {192, 168, 2, 3},
    {100, 64, 2, 3},
    {0, 0, 0, 0, 0, 0, 0, 1},
    {0, 0, 0, 0, 0, 0, 0, 0},
    {0xFC00, 0, 0, 0, 0, 0, 0, 1},
    {0xFE80, 0, 0, 0, 0, 0, 0, 1},
    {0, 0, 0, 0, 0, 0xFFFF, 0x0A01, 0x0203}
  ]
  @public_address {192, 0, 2, 1}

  setup do
    previous_lookup = :inet_db.res_option(:lookup)

    hosts =
      [@public_address | @private_addresses]
      |> Enum.with_index()
      |> Enum.map(fn {address, index} -> {address, ~c"guard-#{index}.example"} end)

    Enum.each(hosts, fn {address, name} -> :inet_db.add_host(address, [name]) end)
    :inet_db.set_lookup([:file])

    on_exit(fn ->
      Enum.each(hosts, fn {address, _name} -> :inet_db.del_host(address) end)
      :inet_db.set_lookup(previous_lookup)
    end)

    {:ok, hosts: hosts}
  end

  test "rejects every private address class after hostname resolution", %{hosts: hosts} do
    for {_address, name} <- Enum.drop(hosts, 1) do
      assert {:error, :private_address} =
               UrlGuard.check("https://#{name}/metadata", allow_private_hosts: false)
    end
  end

  test "allows a hostname that resolves only to a public address", %{hosts: hosts} do
    {_address, name} = hd(hosts)
    assert :ok = UrlGuard.check("https://#{name}/mcp", allow_private_hosts: false)
  end
end
