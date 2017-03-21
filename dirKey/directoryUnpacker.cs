using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;
using System.Linq;

namespace dirKey
{
	public class directoryUnpacker : directoryBase
	{
		private Stopwatch sw = new Stopwatch();
		private bool debug;

		public directoryUnpacker(DirectoryInfo root)
		{
			this.root = root;
			debug = false;
		}

		public directoryUnpacker(DirectoryInfo root, bool debug)
		{
			this.root = root;
			this.debug = debug;
		}

		public void decrypt(keyIterator key)
		{
			/*
			 * Add in a check to make sure this is actually decrypting a real encrypted file
			 * 
			 */
			foreach (string path in fullNames) //should only ever be one, hopefully
			{
				Int64 fileIndex = 0;
				if (debug)
					sw.Start();

				using (FileStream inFile = File.Open(path, FileMode.Open, FileAccess.Read))
				{
					Int64 packSize = inFile.Length;

					//read in the checksum and compare
					byte[] check = new byte[64];
					byte[] checksum = new byte[64];
					for (int i = 0; i < 64; i++)
					{
						check[i] = (byte)(inFile.ReadByte() ^ key.getKeyByte());
					}
					for (int i = 0; i < 64; i++)
					{
						checksum[i] = (byte)(inFile.ReadByte() ^ key.getKeyByte());
					}
					check = SHA512.Create().ComputeHash(check);

					if (!check.SequenceEqual(checksum))
					{
						Console.WriteLine("File {0} is not an encrypted file, or an incorrect key has been selected.", path);
						continue;
					}
					else {
						Console.WriteLine("Decrypting {0}", path);
					}
					fileIndex += 128;

					while (fileIndex < packSize)
					{
						string outName = "";
						List<byte> decBytes = new List<byte>();
						//get the name length

						/*
						 * Uint16 namelength | byte saltByteP | byte saltByteS | string saltedName (up to 260 chars + 512 salt) | Uint32 fileSize | byte[] file |   <repeats>
						 *         2         |        1       |        1       |                 up to 772                      |        4        |   up to 4GB | = 780 bytes
						 */

						//int nameLength = (int)(inFile.ReadByte() ^ key.getKeyByte());
						byte[] nameLengthBytes = new byte[2];
						for (int i = 0; i < 2; i++)
						{
							nameLengthBytes[i] = (byte)(inFile.ReadByte() ^ key.getKeyByte());
						}
						fileIndex += 2;

						UInt16 nameLength = BitConverter.ToUInt16(nameLengthBytes, 0);

						if (debug)
							Console.WriteLine("Length of file name is: {0}", nameLength);

						//get the name out of the file
						List<byte> byteNameRaw = new List<byte>();
						List<byte> byteName = new List<byte>();
						int prefixLength = (inFile.ReadByte() ^ key.getKeyByte());
						int suffixLength = (inFile.ReadByte() ^ key.getKeyByte());
						fileIndex += 2;

						if (debug)
							Console.WriteLine("Prefix and Suffix lengths: {0}, {1}", prefixLength, suffixLength);

						for (int i = 0; i < nameLength + prefixLength + suffixLength; i++)
						{
							byteNameRaw.Add((byte)(inFile.ReadByte() ^ key.getKeyByte()));
						}
						fileIndex += nameLength + prefixLength + suffixLength;

						//take only the filename out
						for (int i = 0; i < nameLength; i++)
						{
							byteName.Add(byteNameRaw[i + prefixLength]);
						}
						outName = Encoding.Unicode.GetString(byteName.ToArray());

						Console.WriteLine("Extracting {0}", outName);

						byte[] fileSizeBytes = new byte[4];
						for (int i = 0; i < 4; i++)
						{
							fileSizeBytes[i] = (byte)(inFile.ReadByte() ^ key.getKeyByte());
						}
						fileIndex += 4;
						UInt32 inFileSize = BitConverter.ToUInt32(fileSizeBytes, 0);

						//Attempt to create directory, just to be sure
						Directory.CreateDirectory(Path.GetDirectoryName(root + "\\" + outName));
						//now get the rest of the file
						if (debug)
							Console.WriteLine(("Writing to: " + Path.GetDirectoryName(path) + "\\" + outName + "\n"));
						using (FileStream outFile = File.Open((Path.GetDirectoryName(path) + "\\" + outName), FileMode.Append))
						{
							//FileInfo inFileSize = new FileInfo(path);
							for (int i = 0; i < inFileSize; i++)//fileToDecrypt.Length; i++)
							{
								outFile.WriteByte((byte)(inFile.ReadByte() ^ key.getKeyByte()));
							}
						}
						fileIndex += (int)inFileSize;
						if (debug)
						{
							Console.WriteLine("File index is {0}", fileIndex);
							Console.WriteLine("Length of extracted Data is {0}", 4 + byteNameRaw.Count + 4 + inFileSize);
						}
					}
				}
				File.Delete(path);

				if (debug)
				{
					sw.Stop();
					Console.WriteLine("Elapsed time: {0}\n", sw.Elapsed);
					sw.Reset();
				}
				key.resetKey();
			}
		}

		public void decryptSingle(keyIterator key, string path)
		{
			//Change the root, ugly to do it here but whatever
			root = new DirectoryInfo(Path.GetDirectoryName(root.FullName));

			Int64 fileIndex = 0;
			if (debug)
				sw.Start();

			using (FileStream inFile = File.Open(path, FileMode.Open, FileAccess.Read))
			{
				Int64 packSize = inFile.Length;

				//read in the checksum and compare
				byte[] check = new byte[64];
				byte[] checksum = new byte[64];
				for (int i = 0; i < 64; i++)
				{
					check[i] = (byte)(inFile.ReadByte() ^ key.getKeyByte());
				}
				for (int i = 0; i < 64; i++)
				{
					checksum[i] = (byte)(inFile.ReadByte() ^ key.getKeyByte());
				}
				check = SHA512.Create().ComputeHash(check);

				if (!check.SequenceEqual(checksum))
				{
					Console.WriteLine("File {0} is not an encrypted file, or an incorrect key has been selected.", path);
					return;
				}
				else {
					Console.WriteLine("Decrypting {0}", path);
				}
				fileIndex += 128;

				while (fileIndex < packSize)
				{
					string outName = "";
					List<byte> decBytes = new List<byte>();
					//get the name length

					/*
					 * Uint16 namelength | byte saltByteP | byte saltByteS | string saltedName (up to 260 chars + 512 salt) | Uint32 fileSize | byte[] file |   <repeats>
					 *         2         |        1       |        1       |                 up to 772                      |        4        |   up to 4GB | = 780 bytes
					 */

					//int nameLength = (int)(inFile.ReadByte() ^ key.getKeyByte());
					byte[] nameLengthBytes = new byte[2];
					for (int i = 0; i < 2; i++)
					{
						nameLengthBytes[i] = (byte)(inFile.ReadByte() ^ key.getKeyByte());
					}
					fileIndex += 2;

					UInt16 nameLength = BitConverter.ToUInt16(nameLengthBytes, 0);

					if (debug)
						Console.WriteLine("Length of file name is: {0}", nameLength);

					//get the name out of the file
					List<byte> byteNameRaw = new List<byte>();
					List<byte> byteName = new List<byte>();
					int prefixLength = (inFile.ReadByte() ^ key.getKeyByte());
					int suffixLength = (inFile.ReadByte() ^ key.getKeyByte());
					fileIndex += 2;

					if (debug)
						Console.WriteLine("Prefix and Suffix lengths: {0}, {1}", prefixLength, suffixLength);

					for (int i = 0; i < nameLength + prefixLength + suffixLength; i++)
					{
						byteNameRaw.Add((byte)(inFile.ReadByte() ^ key.getKeyByte()));
					}
					fileIndex += nameLength + prefixLength + suffixLength;

					//take only the filename out
					for (int i = 0; i < nameLength; i++)
					{
						byteName.Add(byteNameRaw[i + prefixLength]);
					}
					outName = Encoding.Unicode.GetString(byteName.ToArray());

					Console.WriteLine("Extracting {0}", outName);

					byte[] fileSizeBytes = new byte[4];
					for (int i = 0; i < 4; i++)
					{
						fileSizeBytes[i] = (byte)(inFile.ReadByte() ^ key.getKeyByte());
					}
					fileIndex += 4;
					UInt32 inFileSize = BitConverter.ToUInt32(fileSizeBytes, 0);

					//Attempt to create directory, just to be sure
					Directory.CreateDirectory(Path.GetDirectoryName(root + "\\" + outName));
					//now get the rest of the file
					if (debug)
						Console.WriteLine(("Writing to: " + Path.GetDirectoryName(path) + "\\" + outName + "\n"));
					using (FileStream outFile = File.Open((Path.GetDirectoryName(path) + "\\" + outName), FileMode.Append))
					{
						//FileInfo inFileSize = new FileInfo(path);
						for (int i = 0; i < inFileSize; i++)//fileToDecrypt.Length; i++)
						{
							outFile.WriteByte((byte)(inFile.ReadByte() ^ key.getKeyByte()));
						}
					}
					fileIndex += (int)inFileSize;
					if (debug)
					{
						Console.WriteLine("File index is {0}", fileIndex);
						Console.WriteLine("Length of extracted Data is {0}", 4 + byteNameRaw.Count + 4 + inFileSize);
					}
				}
			}
			File.Delete(path);

			if (debug)
			{
				sw.Stop();
				Console.WriteLine("Elapsed time: {0}\n", sw.Elapsed);
				sw.Reset();
			}
			key.resetKey();
		}
	}
}