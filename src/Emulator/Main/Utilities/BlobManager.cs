//
// Copyright (c) 2010-2018 Antmicro
// Copyright (c) 2011-2015 Realtime Embedded
//
// This file is licensed under the MIT License.
// Full license text is available in 'licenses/MIT.txt'.
//
using System;
using Antmicro.Migrant;
using System.Collections.Generic;
using System.IO;

namespace Antmicro.Renode.Utilities
{
    public class BlobManager
    {
        public BlobManager()
        {
            providers = new List<IBlobProvider>();
        }

        // public void Load(FileStream stream)
        // {
        //     Console.WriteLine("^^^^^^^Load in Blobmanager^^^^^^^");
        //     using (var reader = new PrimitiveReader(stream, false))
        //     {
        //         foreach(var provider in providers)
        //         {
        //             var tempFile = TemporaryFilesManager.Instance.GetTemporaryFile();
        //             if(ConfigurationManager.Instance.Get("file-system", "use-cow", false))
        //             {
        //                 FileCopier.Copy(stream.Name, tempFile, true);

        //                 var size = reader.ReadInt64();
        //                 var localPosition = stream.Position;
        //                 reader.ReadBytes((int)size);
        //                 provider.BlobIsReady(tempFile, localPosition, size);
        //             }
        //             else
        //             {
        //                 var size = reader.ReadInt64();
        //                 using(var fileStream = new FileStream(tempFile, FileMode.OpenOrCreate))
        //                 {
        //                     reader.CopyTo(fileStream, size);
        //                 }
        //                 provider.BlobIsReady(tempFile, 0, size);
        //             }
        //         }
        //     }
        // }
        

        //Modified

        public void Load(FileStream stream)
        {
            // Console.WriteLine("^^^^^^^Load in Blobmanager^^^^^^^");
            using (var reader = new PrimitiveReader(stream, false))
            {
                foreach(var provider in providers)
                {
                    var tempFile = TemporaryFilesManager.Instance.GetTemporaryFile();
                    if(ConfigurationManager.Instance.Get("file-system", "use-cow", false))
                    {
                        FileCopier.Copy(stream.Name, tempFile, true);

                        var size = reader.ReadInt64();
                        var localPosition = stream.Position;
                        reader.ReadBytes((int)size);
                        provider.BlobIsReady(tempFile, localPosition, size);
                    }
                    else
                    {
                        var size = reader.ReadInt64();
                        using(var fileStream = new FileStream(tempFile, FileMode.OpenOrCreate))
                        {
                            reader.CopyTo(fileStream, size);
                        }
                        provider.BlobIsReady(tempFile, 0, size);
                    }

                    // // Use a MemoryStream to store the blob data instead of a temporary file
                    // using (var memoryStream = new MemoryStream())
                    // {
                    //     var size = reader.ReadInt64(); // Read the size of the blob
                    //     reader.CopyTo(memoryStream, size); // Copy the data into memory stream

                    //     // Now, instead of a temporary file, pass the MemoryStream to the provider
                    //     provider.BlobIsReady(memoryStream, 0, size); // Use MemoryStream directly
                    // }
                }
            }
        }
        public void Register(IBlobProvider provider)
        {
            providers.Add(provider);
        }

        public void Save(Stream stream)
        {
            //Console.WriteLine("^^^^^^^Save in Blobmanager^^^^^^^");
            using(var writer = new PrimitiveWriter(stream, false))
            {
                foreach(var provider in providers)
                {
                   // Console.WriteLine($"^^^^^^^Save in Blobmanager : {provider}^^^^^^^");
                    var descriptor = provider.GetBlobDescriptor();
                    writer.Write(descriptor.Size);
                    writer.CopyFrom(descriptor.Stream, descriptor.Size);
                }
            }
        }

        [Constructor]
        private readonly List<IBlobProvider> providers;
    }
}

