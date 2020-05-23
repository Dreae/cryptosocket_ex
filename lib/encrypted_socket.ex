defmodule CryptosocketEx.EncryptedSocket do
  @type child_state :: term

  @callback init() :: child_state
  @callback handle_data(bitstring, child_state) :: :ok | {:error, child_state}
  @callback get_key(String.t, child_state) :: {:ok, String.t, child_state} | {:error, term, child_state}

  defmacro __using__(_opts) do
    quote location: :keep do
      @behaviour CryptosocketEx.EncryptedSocket

      alias CryptosocketEx.EncryptedSocket

      use GenServer
      require Logger

      def start_link(socket) do
        GenServer.start_link(__MODULE__, socket)
      end

      def init(socket) do
        :inet.setopts(socket, [active: true])
        nonce_seed = :crypto.strong_rand_bytes(32)
        child_state = init()
        {:ok, %{session_key: nil, key_id: nil, socket: socket, nonce_seed: nonce_seed, nonce_counter: 0, child_state: child_state}}
      end

      def handle_info({:tcp, socket, data}, %{session_key: nil, child_state: child_state} = state) do
        Logger.debug("Got handshake packet")
        <<client_pk::binary-size(32), rest::binary>> = data
        {pos, _} = :binary.match(rest, <<0>>)
        <<key_id::binary-size(pos), 0, mac::binary>> = rest

        {:ok, key, child_state} = get_key(key_id, child_state)
        derived_key = :crypto.hash(:sha512, key)

        computed_mac = :crypto.mac(:hmac, :sha512, :binary.part(derived_key, {0, 32}), client_pk <> key_id <> <<0>>)
        computed_mac = :binary.part(computed_mac, {0, 32})
        if (computed_mac !== mac) do
          Logger.error("Computed signature does not match packet signature")

          {:stop, :bad_handshake, %{state | nonce_seed: nil, child_state: child_state}}
        else
          {public_key, private_key} = :crypto.generate_key(:ecdh, :x25519)
          scalar_mult_key = :crypto.compute_key(:ecdh, client_pk, private_key, :x25519)
          session_key = :crypto.hash(:sha512, scalar_mult_key <> client_pk <> public_key)

          packet = public_key <> key_id <> <<0>>
          signature = :crypto.mac(:hmac, :sha512, :binary.part(derived_key, {0, 32}), packet)

          :gen_tcp.send(socket, packet <> :binary.part(signature, {0, 32}))
          Logger.debug("Handshake complete")

          {:noreply, %{state | session_key: session_key, key_id: key_id, child_state: child_state}}
        end
      end

      def handle_info({:tcp, client, data}, %{session_key: session_key, key_id: key_id, child_state: child_state} = state) do
        Logger.debug("Got data packet")
        <<nonce::binary-size(12), rest::binary>> = data
        ciphertext = :binary.part(rest, {0, byte_size(rest) - 16})
        tag = :binary.part(rest, {byte_size(rest), -16})
        plaintext = :crypto.crypto_one_time_aead(:chacha20_poly1305, session_key, nonce, ciphertext, key_id, tag, false)

        case handle_data(plaintext, child_state) do
          {:ok, child_state} -> {:noreply, %{state | child_state: child_state}}
          {:error, err, child_state} -> {:stop, err, %{state | child_state: child_state}}
        end
      end

      def handle_info({:tcp_closed, _socket}, state) do
        {:stop, :disconnected, %{state | nonce_seed: nil, session_key: nil}}
      end

      def handle_info({:send, data}, %{socket: socket, session_key: session_key, key_id: key_id, nonce_seed: nonce_seed, nonce_counter: counter} = state) do
        nonce = :crypto.hash(:sha3_512, nonce_seed <> <<counter>>)
        nonce = :binary.part(nonce, {0, 12})
        {ciphertext, tag} = :crypto.crypto_one_time_aead(:chacha20_poly1305, session_key, nonce, data, key_id, true)
        :gen_tcp.send(socket, nonce <> ciphertext <> tag)

        {:noreply, %{state | nonce_counter: counter + 1}}
      end
    end
  end

  def send_encrypted(pid, data) do
    send(pid, {:send, data})
  end
end
