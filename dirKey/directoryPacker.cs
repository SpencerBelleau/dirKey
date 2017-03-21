using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;
using System.Linq;

namespace dirKey
{
	public class directoryPacker : directoryBase
	{
		private Stopwatch sw = new Stopwatch();
		private bool debug;

		public directoryPacker(DirectoryInfo root)
		{
			this.root = root;
			debug = false;
		}

		public directoryPacker(DirectoryInfo root, bool debug)
		{
			this.root = root;
			this.debug = debug;
		}

		public void encrypt(keyIterator key)
		{
			MD5 nameGen = MD5.Create();
			//This is really yuge so I split it up
			List<byte> hashInfo = new List<byte>();
			foreach (string s in fullNames)
			{
				hashInfo.AddRange(Encoding.Unicode.GetBytes(s));
			}
			foreach (string s in fullDirs)
			{
				hashInfo.AddRange(Encoding.Unicode.GetBytes(s));
			}
			string outName = 
				DateTime.Today.ToString("d").Replace(@"/", "-") + 
		        "-" + 
		        BitConverter.ToString(
					nameGen.ComputeHash(
						        hashInfo.ToArray()
					)
				).Replace("-", "").ToLower().Substring(0,10);
			Console.WriteLine("Writing to pack: {0}\\{1}", root.FullName, outName);
			using (FileStream outFile = File.Open((root.FullName + "\\" + outName), FileMode.Append, FileAccess.Write))
			{
				var salter = new RNGCryptoServiceProvider();
				byte[] check = new byte[64];
				salter.GetNonZeroBytes(check);
				byte[] checksum = SHA512.Create().ComputeHash(check);

				for (int i = 0; i < 64; i++)
				{
					//Console.Write("{0} ", check[i]);
					outFile.WriteByte((byte)(check[i] ^ key.getKeyByte()));
				}

				for (int i = 0; i < 64; i++)
				{
					//Console.Write("{0} ", checksum[i]);
					outFile.WriteByte((byte)(checksum[i] ^ key.getKeyByte()));
				}

				foreach (string path in fullNames)
				{
					//Possibly replace this lock with a custom function that waits until the file is accessible or a certain amount of time has passed
					int retryMax = 3;
					while (retryMax > 0)
					{
						try
						{
							using (FileStream inFile = File.Open(path, FileMode.Open, FileAccess.Read))
							{
								if (debug)
									sw.Start();
								//first, get the file's name
								string name = path.Substring(root.FullName.Length + 1); //get the relative path
								Console.WriteLine("Encrypting " + name);
								//we also need the bytes of the name
								byte[] nameBytes = Encoding.Unicode.GetBytes(name);
								UInt16 nameLength = (UInt16)nameBytes.Length; //Should always be sub 255, most of the time
								if (debug) Console.WriteLine("Name Length is: {0}", nameLength);
								//generate a byte for the amount of salt that is to be produced
								byte saltByteP = 0, saltByteS = 255;
								//Kind of random? It's close enough for this
								foreach (byte b in nameBytes)
								{
									saltByteP = (byte)(saltByteP ^ b);
									saltByteS = (byte)(saltByteS ^ b);
								}
								if (debug) Console.WriteLine("Salt Bytes are {0}, {1}", saltByteP, saltByteS);

								byte[] prefix = new byte[saltByteP];
								salter.GetNonZeroBytes(prefix);

								byte[] suffix = new byte[saltByteS];
								salter.GetNonZeroBytes(suffix);

								//Put the salt on the ends of the name
								List<byte> saltedName = new List<byte>();
								for (int i = 0; i < saltByteP; i++)
								{
									saltedName.Add(prefix[i]);
								}
								saltedName.AddRange(nameBytes);
								for (int i = 0; i < saltByteS; i++)
								{
									saltedName.Add(suffix[i]);
								}
								if (debug) Console.WriteLine("Length of salted name is: " + saltedName.Count);
								//get the length of the file as Uint32
								UInt32 fileSize = (UInt32)(new FileInfo(path)).Length;

								//Create the "header" and write it
								List<byte> headerBytes = new List<byte>();
								headerBytes.AddRange(BitConverter.GetBytes(nameLength));
								headerBytes.Add(saltByteP);
								headerBytes.Add(saltByteS);
								headerBytes.AddRange(saltedName.ToArray());
								headerBytes.AddRange(BitConverter.GetBytes(fileSize));

								/*
								 * Uint16 namelength | byte saltByteP | byte saltByteS | string saltedName (up to 260 chars + 512 salt) | Uint32 fileSize | byte[] file |   <repeats>
								 *         2         |        1       |        1       |                 up to 772                      |        4        |   up to 4GB | = 780 bytes
								 */

								//if (this.debug) Console.WriteLine(("Writing to: " + Path.GetDirectoryName(path) + "\\" + outName + "\n"));

								foreach (byte b in headerBytes)
								{
									outFile.WriteByte((byte)(b ^ key.getKeyByte()));
								}
								//Write in the rest of the file, byte by byte
								if (debug) Console.WriteLine("Reading: {0}\\{1}", root.FullName, name);

								//FileInfo inFileSize = new FileInfo(path);
								for (int i = 0; i < fileSize; i++)
								{
									outFile.WriteByte((byte)(inFile.ReadByte() ^ key.getKeyByte()));
								}
							}
							if (debug) Console.WriteLine("Done!\n");

							File.Delete(path);
							//key.resetKey();
							if (debug)
							{
								sw.Stop();
								Console.WriteLine("Elapsed time: {0}\n", sw.Elapsed);
								sw.Reset();
							}
							break; //exit the inner retry loop
						}
						catch (Exception e)
						{
							Console.WriteLine("Could not encrypt: {0}, reason: {1}", path, e.Message);
							if (retryMax == 0)
							{
								Console.WriteLine("Failed to encrypt file: {0}", path);
								Console.ReadKey();
							}
							else
							{
								Console.WriteLine("Retrying in 3 seconds...");
								retryMax -= 1;
								System.Threading.Thread.Sleep(3000);
							}
						}
					}
				}
			}
			cleanRoot();
		}
	}
}