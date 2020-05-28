defmodule CryptosocketEx.EncryptedSocket do
  @type child_state :: term

  @callback init() :: child_state
  @callback handle_data(bitstring, child_state) :: {:ok, child_state} | {:error, child_state}
  @callback get_key(String.t, child_state) :: {:ok, String.t, child_state} | {:error, term, child_state}

  defmacro __using__(_opts) do
    quote location: :keep do
      @behaviour CryptosocketEx.EncryptedSocket

      alias CryptosocketEx.EncryptedSocket
      alias CryptosocketEx.Crypto

      use GenServer
      require Logger

      def start_link(socket) do
        GenServer.start_link(__MODULE__, socket)
      end

      def init(socket) do
        :inet.setopts(socket, [active: true])
        nonce_seed = :crypto.strong_rand_bytes(32)
        child_state = init()
        {:ok, %{c_r: nil, c_m: nil, key_id: nil, socket: socket, child_state: child_state}}
      end

      def handle_info({:tcp, socket, data}, %{c_r: nil, c_m: nil, child_state: child_state} = state) do
        Logger.debug("Got handshake packet")
        <<client_pk::binary-size(32), salt::binary-size(32), rest::binary>> = data
        {pos, _} = :binary.match(rest, <<0>>)
        <<key_id::binary-size(pos), 0, mac::binary>> = rest

        {:ok, key, child_state} = get_key(key_id, child_state)
        derived_key = Crypto.hkdf(salt, key, "SMCRYPTO_KEY", 32)

        computed_mac = :crypto.mac(:hmac, :sha512, derived_key, client_pk <> salt <> key_id <> <<0>>)
        computed_mac = :binary.part(computed_mac, {0, 32})
        if (computed_mac !== mac) do
          Logger.error("Computed signature does not match packet signature")

          {:stop, :bad_handshake, %{state | child_state: child_state}}
        else
          {public_key, private_key} = :crypto.generate_key(:ecdh, :x25519)
          scalar_mult_key = :crypto.compute_key(:ecdh, client_pk, private_key, :x25519)
          <<c_m::binary-size(32), c_r::binary-size(32)>> = Crypto.hkdf(scalar_mult_key <> client_pk <> public_key, <<1>>, 64)
          packet = public_key <> salt <> key_id <> <<0>>
          signature = :crypto.mac(:hmac, :sha512, derived_key, packet)

          :gen_tcp.send(socket, packet <> :binary.part(signature, {0, 32}))
          Logger.debug("Handshake complete")

          {:noreply, %{state | c_r: c_r, c_m: c_m, key_id: key_id, child_state: child_state}}
        end
      end

      def handle_info({:tcp, client, data}, %{c_r: c_r, key_id: key_id, child_state: child_state} = state) do
        Logger.debug("Got data packet")
        ciphertext = :binary.part(data, {0, byte_size(data) - 16})
        tag = :binary.part(data, {byte_size(data), -16})
        <<key::binary-size(32), nonce::binary-size(12)>> = Crypto.hkdf(c_r, "SMCRYPTO_KEYS", 44)
        c_r = :binary.part(:crypto.mac(:hmac, :sha512, c_r, <<2>>), {0, 32})
        plaintext = :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, ciphertext, key_id, tag, false)

        case handle_data(plaintext, child_state) do
          {:ok, child_state} -> {:noreply, %{state | c_r: c_r, child_state: child_state}}
          {:error, err, child_state} -> {:stop, err, %{state | c_r: c_r, child_state: child_state}}
        end
      end

      def handle_info({:tcp_closed, _socket}, state) do
        {:stop, :disconnected, %{state | c_r: nil, c_m: nil}}
      end

      def handle_info({:send, data}, %{socket: socket, key_id: key_id, c_m: c_m} = state) do
        <<key::binary-size(32), nonce::binary-size(12)>> = Crypto.hkdf(c_m, "SMCRYPTO_KEYS", 44)
        c_m = :binary.part(:crypto.mac(:hmac, :sha512, c_m, <<2>>), {0, 32})

        {ciphertext, tag} = :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, data, key_id, true)
        :gen_tcp.send(socket, ciphertext <> tag)

        {:noreply, %{state | c_m: c_m}}
      end
    end
  end

  def send_encrypted(pid, data) do
    send(pid, {:send, data})
  end
end
