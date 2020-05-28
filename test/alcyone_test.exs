defmodule AlcyoneTest do
  use ExUnit.Case
  doctest Alcyone

  alias Alcyone.Utils

  test "greets the world" do
    assert Alcyone.hello() == :world
  end

  test "var int decode" do
    assert Utils.decode_var_int(<<0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C>>) ==
             {151_288_809_941_952_652, 8}

    assert Utils.decode_var_int(<<0x9D, 0x7F, 0x3E, 0x7D>>) ==
             {494_878_333, 4}

    assert Utils.decode_var_int(<<0x7B, 0xBD>>) ==
             {15293, 2}

    assert Utils.decode_var_int(<<0x40, 0x25>>) ==
             {37, 2}

    assert Utils.decode_var_int(<<0x25>>) ==
             {37, 1}
  end
end
