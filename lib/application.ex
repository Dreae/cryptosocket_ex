defmodule CryptosocketEx.Application do
  use Application

  def start(_, _) do
    children = [
      {DynamicSupervisor, name: CryptosocketEx.Supervisor, strategy: :one_for_one}
    ]

    Supervisor.start_link(children, strategy: :one_for_one)
  end
end
