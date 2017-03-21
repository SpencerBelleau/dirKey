using System.Collections.Generic;

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

		public keyIterator(byte[] data)
		{
			this.data = new byte[data.Length];
			data.CopyTo(this.data, 0);

			originalData = new byte[data.Length];
			data.CopyTo(originalData, 0);

			keyLength = data.Length;
			index = 0; //initialize
			indexOffset = 0;
		}
		public byte getKeyByte()
		{
			incrementIndex();
			return data[(data[index] + data[indexOffset]) % keyLength];
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
			index = (index + 1) % keyLength;
			indexOffset = (indexOffset + data[index]) % keyLength;
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
				output.Add((byte)(input[i] ^ getKeyByte()));
			}
			return output.ToArray();
		}

		//Called after encryption is finished
		public void resetKey()
		{
			originalData.CopyTo(data, 0);
			keyLength = data.Length;
			index = 0;
			indexOffset = 0;
		}
	}
}
