defmodule CryptosocketEx.Agent do
  require Logger

  def child_spec(arg) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, arg}
    }
  end

  def start_link(socket_module, options \\ []) do
    address = Keyword.get(options, :address, "127.0.0.1")
    port = Keyword.get(options, :port, 4647)

    {:ok, addr} = :inet.parse_address(to_charlist(address))
    Task.start_link(__MODULE__, :start_listen, [socket_module, addr, port])
  end

  def start_listen(socket_module, addr, port) do
    Logger.info("Listening on #{:inet.ntoa(addr)}:#{port}")
    {:ok, socket} = :gen_tcp.listen(port, [:binary, packet: 2, active: false, reuseaddr: true, ip: addr])
    loop_accept(socket_module, socket)
  end

  def loop_accept(socket_module, socket) do
    {:ok, client} = :gen_tcp.accept(socket)
    {:ok, pid} = DynamicSupervisor.start_child(CryptosocketEx.Supervisor, {socket_module, client})
    :ok = :gen_tcp.controlling_process(client, pid)

    loop_accept(socket_module, socket)
  end
end
