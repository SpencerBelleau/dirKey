using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace dirKey
{
	/*
	 * Basically just a holder object for the key
	 * Also it handles the iteration through the key bytes
	 * The key uses a method similar to RC4 to pseudorandomly select bytes from within it to XOR with the data
	 * This should provide decent security, though of course it does depends on key length
	 */
	public class keyIterator
	{
		private byte[] data;
		private byte[] originalData; //this value should never change
		private int keyLength;
		private int index;
		private int indexOffset;
		//private SHA1 checkSum = SHA1.Create();

		public keyIterator(byte[] data)
		{
			this.data = new byte[data.Length];
			data.CopyTo(this.data, 0);

			this.originalData = new byte[data.Length];
			data.CopyTo(this.originalData, 0);

			this.keyLength = data.Length;
			this.index = 0; //initialize
			this.indexOffset = 0;
		}
		public byte getKeyByte()
		{
			incrementIndex();
			return data[(data[index] + data[indexOffset]) % this.keyLength];
		}
		public void incrementBy(long amount)
		{
			for (long i = 0; i < amount; i++)
			{
				incrementIndex();
			}
		}
		private void incrementIndex()
		{
			//RC4-like thing
			index = (index + 1) % this.keyLength;
			indexOffset = (indexOffset + data[index]) % this.keyLength;
			//swap
			byte tmp = data[indexOffset];
			data[indexOffset] = data[index];
			data[index] = tmp;
		}

		//This isn't really ever used, consider removing it
		public byte[] applyKey(byte[] input)
		{
			List<byte> output = new List<byte>();
			for (int i = 0; i < input.Length; i++)
			{
				output.Add( (byte)(input[i] ^ getKeyByte()) );
			}
			return output.ToArray();
		}

		//Called after encryption is finished
		public void resetKey()
		{
			this.originalData.CopyTo(this.data, 0);
			this.keyLength = data.Length;
			this.index = 0;
			this.indexOffset = 0;
		}
	}
}
