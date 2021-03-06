﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace dirKey
{
	public class packageManipulator : directoryBase
	{
		private bool debug = false;
		private Stopwatch sw = new Stopwatch();

		public packageManipulator(DirectoryInfo root)
		{
			this.root = root;
		}
		public packageManipulator(DirectoryInfo root, bool debug)
		{
			this.root = root;
			this.debug = debug;
		}
		public void listPackage(keyIterator key, string path)
		{
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
					Console.WriteLine("Listing {0}", path);
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

					byte[] fileSizeBytes = new byte[4];
					for (int i = 0; i < 4; i++)
					{
						fileSizeBytes[i] = (byte)(inFile.ReadByte() ^ key.getKeyByte());
					}
					fileIndex += 4;
					UInt32 inFileSize = BitConverter.ToUInt32(fileSizeBytes, 0);

					Console.WriteLine("{0}: {1}", outName, MainClass.BytesToString(inFileSize));

					//Attempt to create directory, just to be sure
					//Directory.CreateDirectory(Path.GetDirectoryName(root + "\\" + outName));
					//now get the rest of the file
					inFile.Position += inFileSize;
					key.incrementBy(inFileSize);
					fileIndex += inFileSize;
				}
			}
			//File.Delete(path);

			if (debug)
			{
				sw.Stop();
				Console.WriteLine("Elapsed time: {0}\n", sw.Elapsed);
				sw.Reset();
			}
			key.resetKey();
		}

		public bool isPackage(string path, keyIterator key)
		{
			if (!MainClass.isFile(path))
			{
				if (debug)
					Console.WriteLine("{0} is not a file", path);
				return false;
			}
			using (FileStream inFile = new FileStream(path, FileMode.Open))
			{
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
				key.resetKey();
				if (!check.SequenceEqual(checksum))
				{
					if (debug)
						Console.WriteLine("{0} failed checksum test", path);
					return false;
				}
				return true;
			}
		}

		public void appendPackage(keyIterator key, string path, string toAdd = null)
		{
			walkDirectory();
			//scan all the files in the directory and find packages
			List<string> packages = new List<string>();
			List<string> files = new List<string>();
			int input = -1;
			bool addingFile = false;
			if (!MainClass.isFile(toAdd))
			{
				addingFile = true; //This will eventually just direct to the file version
			}

			foreach (string s in fullNames)
			{
				if(debug)
					Console.WriteLine(s);
				if (isPackage(s, key))
				{
					if(debug)
						Console.WriteLine("Package found: {0}", s);
					packages.Add(s);
				}
			}
			if (debug)
				Console.WriteLine("Packages added");
			//if there is only one package, proceed
			//if there is more than one, prompt the user to select one
			if (packages.Count > 1)
			{
				Console.WriteLine("Found multiple packages:");
				int i = 0;
				foreach (string package in packages)
				{
					i += 1;
					Console.WriteLine("{0} -> {1}", i, package);
				}
				Console.Write("Select package number to use (or 0 to exit): ");
				while (input != 0 && (input < packages.Count && input != 0))
				{
					input = -1;
					input = Console.Read() - 48; //Changes input into the appropriate number
					if (input > packages.Count || input < 0)
					{
						if (debug)
							Console.WriteLine("Selected package: {0}", input);
						Console.Write("Invalid input, please enter a number between 1 and {0}, or 0 to exit: ", packages.Count);
					}
				}
			}
			else 
			{
				input = 1;
			}
			if (debug)
				Console.WriteLine("Selected package: {0}", input);
			if (input == 0)
			{
				return;
			}
			string selectedPackage = packages[input-1];

			//check toAdd, if it's null, prompt if ok to add all files in root
			if (toAdd.Equals(null))
			{
				Console.Write("No specific addition selected, ok to add all files in {0} (Y/n)?: ", path);
				while (Convert.ToChar(input) != 'Y' && Convert.ToChar(input) != 'n')
				{
					input = Console.Read();
					if (Convert.ToChar(input) != 'Y' && Convert.ToChar(input) != 'n')
					{
						Console.Write("Invalid input, please enter Y or n: ");
					}
				}
				if (Convert.ToChar(input) == 'n')
				{
					return;
				}
				toAdd = root.FullName;
			}
			//if it's a directory, add all files in that directory
			//if it's a file, add that file
			if (MainClass.isFile(toAdd))
			{
				files.Add(toAdd); //This will eventually just direct to the file version
			}
			else
			{
				files.AddRange(directoryBase.getFiles(new DirectoryInfo(toAdd)));
			}

			if (debug)
			{
				Console.WriteLine("Adding Directory: {0}", toAdd);
				Console.WriteLine("Files to add to archive:");
				foreach (string s in files)
				{
					Console.WriteLine("{0}", s);
				}
			}

			//open the package, seek to the end
			using (FileStream package = new FileStream(selectedPackage, FileMode.Append))
			{
				var salter = new RNGCryptoServiceProvider();
				//iterate key by the file size
				key.incrementBy(package.Length);
				//encrypt the file and appends all the bytes of the result to the end

				/*
				 * This bit should also probably be externalized
				 */

				foreach (string filePath in files)
				{
					if (debug)
						Console.WriteLine("Adding file: {0}", filePath);
					int retryMax = 3;
					while (retryMax > 0)
					{
						try
						{
							using (FileStream inFile = File.Open(filePath, FileMode.Open, FileAccess.Read))
							{
								if (debug)
									sw.Start();
								//first, get the file's name
								string name = filePath.Substring(root.FullName.Length + 1); //get the relative path
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
								UInt32 fileSize = (UInt32)(new FileInfo(filePath)).Length;

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
									package.WriteByte((byte)(b ^ key.getKeyByte()));
								}
								//Write in the rest of the file, byte by byte
								if (debug) Console.WriteLine("Reading: {0}\\{1}", root.FullName, name);

								//FileInfo inFileSize = new FileInfo(path);
								for (int i = 0; i < fileSize; i++)
								{
									package.WriteByte((byte)(inFile.ReadByte() ^ key.getKeyByte()));
								}
							}
							if (debug) Console.WriteLine("Done!\n");

							File.Delete(filePath);
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
							Console.WriteLine("Could not encrypt: {0}, reason: {1}", filePath, e.Message);
							if (retryMax == 0)
							{
								Console.WriteLine("Failed to encrypt file: {0}", filePath);
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
					if (!addingFile)
					{
						cleanRoot();
					}
				}
			}
		}
	}
}
