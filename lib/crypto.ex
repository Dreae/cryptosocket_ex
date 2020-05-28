defmodule CryptosocketEx.Crypto do
  def hkdf(key, ctx, out_size) do
    hkdf(<<0::256>>, key, ctx, out_size)
  end

  def hkdf(salt, key, ctx, out_size) do
    prk = :binary.part(:crypto.mac(:hmac, :sha512, salt, key), {0, 32})
    t = <<>>
    okm = <<>>

    stop = round(Float.ceil(out_size / 32))
    hkdf_loop(prk, t, okm, ctx, out_size, 0, stop)
  end

  def hkdf_loop(_prk, _t, okm, _ctx, out_size, _iter, 0) do
    <<out::binary-size(out_size), _rest::binary>> = okm

    out
  end

  def hkdf_loop(prk, t, okm, ctx, out_size, iter, stop) do
    t = :binary.part(:crypto.mac(:hmac, :sha512, prk, t <> ctx <> <<iter + 1>>), {0, 32})
    hkdf_loop(prk, t, okm <> t, ctx, out_size, iter + 1, stop - 1)
  end
end
