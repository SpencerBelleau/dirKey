using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;

namespace dirKey
{
	public class directoryEncrypter
	{
		private System.IO.DirectoryInfo root;
		private List<String> fullNames = new List<string>();
		private Stopwatch sw = new Stopwatch();
		private bool debug;

		public directoryEncrypter(System.IO.DirectoryInfo root)
		{
			this.root = root;
			this.debug = false;
		}

		public directoryEncrypter(System.IO.DirectoryInfo root, bool debug)
		{
			this.root = root;
			this.debug = debug;
		}

		public void walkDirectory()
		{
			walkDirectory(this.root);
		}

		public void walkDirectory(System.IO.DirectoryInfo root)
		{
			System.IO.FileInfo[] fileNames = null;
			System.IO.DirectoryInfo[] subDirs = null;

			try
			{
				fileNames = root.GetFiles("*");
			}
			catch (Exception e)
			{
				Console.WriteLine(e.Message);
			}

			if (fileNames != null)
			{
				foreach (System.IO.FileInfo name in fileNames)
				{
					//Log it
					//Console.WriteLine(name.FullName);
					fullNames.Add(name.FullName);
				}

				subDirs = root.GetDirectories();

				foreach (System.IO.DirectoryInfo subDir in subDirs)
				{
					walkDirectory(subDir);
				}
			}
		}

		public void encrypt(keyIterator key)
		{
			foreach (String path in fullNames)
			{
				if (this.debug)
					sw.Start();
				//first, get the file's name
				String name = Path.GetFileName(path);
				Console.WriteLine("Encrypting " + path);
				//we also need the bytes of the name
				byte[] nameBytes = Encoding.Unicode.GetBytes(name);
				byte lengthByte = (byte)nameBytes.Length; //Should always be sub 255, most of the time
				if(this.debug) Console.WriteLine("Name Length is: {0}", lengthByte);
				//generate a byte for the amount of salt that is to be produced
				byte saltByte = 0;
				//Kind of random? It's close enough for this
				foreach (byte b in nameBytes)
				{
					saltByte = (byte)(saltByte ^ b);
				}
				if (this.debug) Console.WriteLine("Salt Byte is {0}", saltByte);

				var salter = new RNGCryptoServiceProvider();

				int prefixLength = (int)saltByte % 16;
				byte[] prefix = new byte[prefixLength];
				salter.GetNonZeroBytes(prefix);

				int suffixLength = (int)((saltByte - (saltByte % 16)) / 16);
				byte[] suffix = new byte[suffixLength];
				salter.GetNonZeroBytes(suffix);
				if (this.debug) Console.WriteLine("Prefix and Suffix lengths: {0}, {1}", prefixLength, suffixLength);

				//Put the salt on the ends of the name
				List<byte> saltedName = new List<byte>();
				for (int i = 0; i < prefixLength; i++)
				{
					saltedName.Add(prefix[i]);
				}
				saltedName.AddRange(nameBytes);
				for (int i = 0; i < suffixLength; i++)
				{
					saltedName.Add(suffix[i]);
				}
				if (this.debug) Console.WriteLine("Length of salted name is: " + saltedName.Count);

				//Start putting together the new file
				MD5 nameGen = MD5.Create();
				String outName = BitConverter.ToString(nameGen.ComputeHash(nameBytes)).Replace("-", "").ToLower();

				//Create the "header" and write it
				List<byte> headerBytes = new List<byte>();
				headerBytes.Add(lengthByte);
				headerBytes.Add(saltByte);
				headerBytes.AddRange(saltedName.ToArray());

				if (this.debug) Console.WriteLine(("Writing to: " + Path.GetDirectoryName(path) + "\\" + outName + "\n"));

				using (FileStream outFile = File.Open((Path.GetDirectoryName(path) + "\\" + outName), FileMode.Append, FileAccess.Write))
				{
					foreach (byte b in headerBytes)
					{
						outFile.WriteByte((byte)(b ^ key.getKeyByte()));
					}
					//Write in the rest of the file, byte by byte
					using (FileStream inFile = File.Open(path, FileMode.Open, FileAccess.Read))
					{
						FileInfo inFileSize = new FileInfo(path);
						for (int i = 0; i < inFileSize.Length; i++)
						{
							outFile.WriteByte((byte)(inFile.ReadByte() ^ key.getKeyByte()));
						}
					}
				}

				File.Delete(path);
				key.resetKey();
				if (this.debug)
				{
					sw.Stop();
					Console.WriteLine("Elapsed time: {0}\n", sw.Elapsed);
					sw.Reset();
				}
			}
		}


		public void decrypt(keyIterator key)
		{
			foreach (String path in fullNames)
			{
				if (this.debug)
					sw.Start();
				Console.WriteLine("Decrypting {0}", path);

				using (FileStream inFile = File.Open(path, FileMode.Open, FileAccess.Read))
				{
					String outName = "";
					List<byte> decBytes = new List<byte>();
					//get the name length
					int nameLength = (int)(inFile.ReadByte() ^ key.getKeyByte());
					if (this.debug) 
						Console.WriteLine("Length of file name is: {0}", nameLength);

					//get the name out of the file
					List<byte> byteNameRaw = new List<byte>();
					List<byte> byteName = new List<byte>();
					int saltStuff = (int)(inFile.ReadByte() ^ key.getKeyByte());

					if (this.debug) 
						Console.WriteLine("Salt Byte is {0}", saltStuff);

					int prefixLength = (int)saltStuff % 16;
					int suffixLength = (int)((saltStuff - (saltStuff % 16)) / 16);

					if (this.debug) 
						Console.WriteLine("Prefix and Suffix lengths: {0}, {1}", prefixLength, suffixLength);

					for (int i = 0; i < nameLength + prefixLength + suffixLength; i++)
					{
						byteNameRaw.Add((byte)(inFile.ReadByte() ^ key.getKeyByte()));
					}

					//take only the filename out
					for (int i = 0; i < nameLength; i++)
					{
						byteName.Add(byteNameRaw[i + prefixLength]);
					}
					outName = Encoding.Unicode.GetString(byteName.ToArray());

					if (this.debug) 
						Console.WriteLine("Extracted name is: {0}", outName);

					//now get the rest of the file
					if (this.debug) 
						Console.WriteLine(("Writing to: " + Path.GetDirectoryName(path) + "\\" + outName + "\n"));
					using (FileStream outFile = File.Open((Path.GetDirectoryName(path) + "\\" + outName), FileMode.Append))
					{
						FileInfo inFileSize = new FileInfo(path);
						for (int i = 2 + prefixLength + nameLength + suffixLength; i < inFileSize.Length; i++)//fileToDecrypt.Length; i++)
						{
							outFile.WriteByte((byte)(inFile.ReadByte() ^ key.getKeyByte()));
						}
					}
				}
				File.Delete(path);
				key.resetKey();
				if (this.debug)
				{
					sw.Stop();
					Console.WriteLine("Elapsed time: {0}\n", sw.Elapsed);
					sw.Reset();
				}
			}
		}
	}
}
