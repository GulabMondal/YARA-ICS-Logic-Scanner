rule ModbusWriteCoilBackdoor
{
    strings:
        $b = "address=\"40010\""
        $c = "address=\"40011\""
    condition:
        all of them
}
