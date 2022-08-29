using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

public class ProtectedMemory
{
    private byte[] data;
    private char[] chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".ToCharArray();
    private ProtoRandom.ProtoRandom random;

    public ProtectedMemory()
    {
        random = new ProtoRandom.ProtoRandom(5);
        data = new byte[] { };
    }

    public ulong Insert(byte[] value, ulong address = 0)
    {
        while (!IsAddressAvailable(address))
        {
            address = random.GetRandomUInt64(1, ulong.MaxValue - 3);
        }

        byte[] toAdd = BitConverter.GetBytes(address);
        string key = random.GetRandomString(chars, random.GetRandomInt32(10, 25));

        byte[] hash = GetMD5(value);
        value = EncryptAES256(value, key);

        toAdd = Combine(toAdd, BitConverter.GetBytes(value.Length));
        toAdd = Combine(toAdd, value);

        toAdd = Combine(toAdd, BitConverter.GetBytes(key.Length));
        toAdd = Combine(toAdd, Encoding.UTF8.GetBytes(key));

        toAdd = Combine(toAdd, hash);

        if (data.Length == 0)
        {
            data = toAdd;
        }
        else
        {
            data = Combine(data, toAdd);
        }

        return address;
    }

    public ulong Insert(int value, ulong address = 0)
    {
        return Insert(BitConverter.GetBytes(value), address);
    }

    public ulong Insert(long value, ulong address = 0)
    {
        return Insert(BitConverter.GetBytes(value), address);
    }

    public ulong Insert(double value, ulong address = 0)
    {
        return Insert(BitConverter.GetBytes(value), address);
    }

    public ulong Insert(string value, ulong address = 0)
    {
        return Insert(Encoding.Unicode.GetBytes(value), address);
    }

    public ulong Insert(float value, ulong address = 0)
    {
        return Insert(BitConverter.GetBytes(value), address);
    }

    public ulong Insert(short value, ulong address = 0)
    {
        return Insert(BitConverter.GetBytes(value), address);
    }

    public ulong Insert(byte value, ulong address = 0)
    {
        return Insert(BitConverter.GetBytes(value), address);
    }

    public ulong Insert(uint value, ulong address = 0)
    {
        return Insert(BitConverter.GetBytes(value), address);
    }

    public ulong Insert(ulong value, ulong address = 0)
    {
        return Insert(BitConverter.GetBytes(value), address);
    }

    public ulong Insert(sbyte value, ulong address = 0)
    {
        return Insert(BitConverter.GetBytes(value), address);
    }

    public ulong Insert(bool value, ulong address = 0)
    {
        return Insert(BitConverter.GetBytes(value), address);
    }

    public ulong Insert(char value, ulong address = 0)
    {
        return Insert(BitConverter.GetBytes(value), address);
    }

    public ulong Insert(ushort value, ulong address = 0)
    {
        return Insert(BitConverter.GetBytes(value), address);
    }

    public bool IsAddressAvailable(ulong address)
    {
        if (address == 0)
        {
            return false;
        }

        if (data.Length == 0)
        {
            return true;
        }

        byte[] theData = data;

        while (theData.Length > 0)
        {
            if (BitConverter.ToUInt64(theData.Take(8).ToArray(), 0).Equals(address))
            {
                return false;
            }

            theData = theData.Skip(8).ToArray();

            int size = BitConverter.ToInt32(theData.Take(4).ToArray(), 0);
            theData = theData.Skip(4 + size).ToArray();

            int keyLength = BitConverter.ToInt32(theData.Take(4).ToArray(), 0);
            theData = theData.Skip(4 + keyLength + 16).ToArray();
        }

        return true;
    }

    public byte[] GetValue(ulong address, bool delete = false)
    {
        byte[] theData = data;

        while (theData.Length > 0)
        {
            ulong theAddress = BitConverter.ToUInt64(theData.Take(8).ToArray(), 0);
            theData = theData.Skip(8).ToArray();

            int size = BitConverter.ToInt32(theData.Take(4).ToArray(), 0);
            theData = theData.Skip(4).ToArray();

            byte[] data = theData.Take(size).ToArray();
            theData = theData.Skip(size).ToArray();

            int keyLength = BitConverter.ToInt32(theData.Take(4).ToArray(), 0);
            theData = theData.Skip(4).ToArray();

            string key = Encoding.UTF8.GetString(theData.Take(keyLength).ToArray());
            theData = theData.Skip(keyLength).ToArray();
            data = DecryptAES256(data, key);

            byte[] hash = theData.Take(16).ToArray();
            theData = theData.Skip(16).ToArray();

            if (!CompareByteArrays(hash, GetMD5(data)))
            {
                return null;
            }

            if (theAddress == address)
            {
                if (delete)
                {
                    Delete(address);
                }

                return data;
            }
        }

        return null;
    }

    public bool Delete(ulong address)
    {
        bool deleted = false;

        if (address == 0)
        {
            return false;
        }

        if (data.Length == 0)
        {
            return false;
        }

        byte[] newDatas = new byte[] { };
        byte[] theData = data;

        while (theData.Length > 0)
        {
            ulong theAddress = BitConverter.ToUInt64(theData.Take(8).ToArray(), 0);
            theData = theData.Skip(8).ToArray();

            int size = BitConverter.ToInt32(theData.Take(4).ToArray(), 0);
            theData = theData.Skip(4).ToArray();

            byte[] data = theData.Take(size).ToArray();
            theData = theData.Skip(size).ToArray();

            int keyLength = BitConverter.ToInt32(theData.Take(4).ToArray(), 0);
            theData = theData.Skip(4).ToArray();

            string key = Encoding.UTF8.GetString(theData.Take(keyLength).ToArray());
            theData = theData.Skip(keyLength).ToArray();

            byte[] hash = theData.Take(16).ToArray();
            theData = theData.Skip(16).ToArray();

            if (theAddress == address)
            {
                deleted = true;
                continue;
            }

            byte[] united = BitConverter.GetBytes(theAddress);

            united = Combine(united, BitConverter.GetBytes(size));
            united = Combine(united, data);
            united = Combine(united, BitConverter.GetBytes(keyLength));
            united = Combine(united, Encoding.UTF8.GetBytes(key));
            united = Combine(united, hash);

            if (newDatas.Length == 0)
            {
                newDatas = united;
            }
            else
            {
                newDatas = Combine(newDatas, united);
            }
        }

        data = newDatas;
        return deleted;
    }

    public short GetValueAsInt16(ulong address, bool delete = false)
    {
        return BitConverter.ToInt16(GetValue(address, delete), 0);
    }

    public int GetValueAsInt32(ulong address, bool delete = false)
    {
        return BitConverter.ToInt32(GetValue(address, delete), 0);
    }

    public long GetValueAsInt64(ulong address, bool delete = false)
    {
        return BitConverter.ToInt64(GetValue(address, delete), 0);
    }

    public bool GetValueAsBoolean(ulong address, bool delete = false)
    {
        return BitConverter.ToBoolean(GetValue(address, delete), 0);
    }

    public char GetValueAsChar(ulong address, bool delete = false)
    {
        return BitConverter.ToChar(GetValue(address, delete), 0);
    }

    public string GetValueAsString(ulong address, bool delete = false)
    {
        return Encoding.Unicode.GetString(GetValue(address, delete));
    }

    public ulong GetValueAsUInt64(ulong address, bool delete = false)
    {
        return BitConverter.ToUInt64(GetValue(address, delete), 0);
    }

    public uint GetValueAsUInt32(ulong address, bool delete = false)
    {
        return BitConverter.ToUInt32(GetValue(address, delete), 0);
    }

    public ushort GetValueAsUInt16(ulong address, bool delete = false)
    {
        return BitConverter.ToUInt16(GetValue(address, delete), 0);
    }

    public byte GetValueAsByte(ulong address, bool delete = false)
    {
        return GetValue(address, delete)[0];
    }

    public double GetValueAsDouble(ulong address, bool delete = false)
    {
        return BitConverter.ToDouble(GetValue(address, delete), 0);
    }

    private byte[] Combine(byte[] first, byte[] second)
    {
        byte[] ret = new byte[first.Length + second.Length];

        Buffer.BlockCopy(first, 0, ret, 0, first.Length);
        Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);

        return ret;
    }

    private byte[] EncryptAES256(byte[] input, string pass)
    {
        var AES = new RijndaelManaged();
        var hash = new byte[32];
        var temp = new MD5CryptoServiceProvider().ComputeHash(Encoding.Unicode.GetBytes(pass));

        Array.Copy(temp, 0, hash, 0, 16);
        Array.Copy(temp, 0, hash, 15, 16);

        AES.Key = hash;
        AES.Mode = CipherMode.ECB;

        return AES.CreateEncryptor().TransformFinalBlock(input, 0, input.Length);
    }

    private byte[] DecryptAES256(byte[] input, string pass)
    {
        var AES = new RijndaelManaged();
        var hash = new byte[32];
        var temp = new MD5CryptoServiceProvider().ComputeHash(Encoding.Unicode.GetBytes(pass));

        Array.Copy(temp, 0, hash, 0, 16);
        Array.Copy(temp, 0, hash, 15, 16);

        AES.Key = hash;
        AES.Mode = CipherMode.ECB;

        return AES.CreateDecryptor().TransformFinalBlock(input, 0, input.Length);
    }

    private byte[] GetMD5(byte[] data)
    {
        return MD5.Create().ComputeHash(data);
    }

    private bool CompareByteArrays(byte[] first, byte[] second)
    {
        if (first.Length != second.Length)
        {
            return false;
        }

        for (int i = 0; i < first.Length; i++)
        {
            if (first[i] != second[i])
            {
                return false;
            }
        }

        return true;
    }
}