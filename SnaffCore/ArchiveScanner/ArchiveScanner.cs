using SharpCompress.Archives;
using SnaffCore.Concurrency;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Classifiers;
using SharpCompress.Common;
using SharpCompress.Crypto;
using SharpCompress.Readers;
using SnaffCore.Config;
using static SnaffCore.Config.Options;
using CryptographicException = System.Security.Cryptography.CryptographicException;

namespace SnaffCore.ArchiveScan
{
    public class ArchiveScanner
    {
        private BlockingMq Mq { get; set; }
        private String UnpackPath { get; set; }
        private bool UnpackToDisk { get; set; }
        private List<ClassifierRule> FileClassifiers = MyOptions.FileClassifiers;

        public ArchiveScanner()
        {
            Mq = BlockingMq.GetMq();

            if (MyOptions.UnpackArchivesToDisk)
            {
                UnpackToDisk = true;
                UnpackPath = MyOptions.ArchiveUnpackPath;
            }
        }

        public bool ScanArchive(FileInfo fileInfo)
        {
            bool atLeastOneContentsMatch = false;
            // look inside archives for files we like.
            try
            {
                using (Stream stream = File.OpenRead(fileInfo.FullName))
                using (var reader = ReaderFactory.Open(stream))
                {
                    while (reader.MoveToNextEntry())
                    {
                        if (!reader.Entry.IsDirectory)
                        {
                            try
                            {
                                if (ScanFileInArchive(reader.Entry.Key, fileInfo.FullName))
                                {
                                    atLeastOneContentsMatch = true;
                                }
                            }
                            catch (Exception e)
                            {
                                Mq.Trace(e.ToString());
                            }
                        }
                    }
                }
            }
            catch (System.InvalidOperationException e)
            {
                Mq.Degub("Snaffler couldn't figure out how to unpack " + fileInfo.FullName);
                Mq.Trace(e.ToString());
            }
            catch (SharpCompress.Common.CryptographicException)
            {
                Mq.FileResult(new FileResult(fileInfo)
                {
                    MatchedRule = new ClassifierRule() {Triage = Triage.Red, RuleName = "EncryptedArchive"}
                });
            }
            catch (System.ArgumentNullException e)
            {
                Mq.FileResult(new FileResult(fileInfo)
                {
                    MatchedRule = new ClassifierRule() {Triage = Triage.Red, RuleName = "EncryptedArchive"}
                });
            }
            catch (System.IO.EndOfStreamException e)
            {
                Mq.Trace(e.ToString());
            }
            catch (Exception e)
            {
                Mq.Degub(e.ToString());
            }

            return atLeastOneContentsMatch;
        }

        public bool ScanFileInArchive(string entryFile, string archiveFilePath)
        {
            FileInfo fakeEntryFileInfo = new FileInfo(Path.GetFullPath(Path.Combine(archiveFilePath, entryFile)));
            try
            {
                // send the file to all the classifiers.
                foreach (ClassifierRule classifier in FileClassifiers)
                {
                    // Make sure we're only looking at simple filename stuff here:
                    if ((classifier.MatchAction == MatchAction.Snaffle) ||
                        (classifier.MatchAction == MatchAction.Discard))
                    {
                        if ((classifier.MatchLocation == MatchLoc.FileExtension) ||
                            (classifier.MatchLocation == MatchLoc.FileName) ||
                            (classifier.MatchLocation == MatchLoc.FilePath))
                        {
                            FileClassifier fileClassifier = new FileClassifier(classifier);
                            if (fileClassifier.ClassifyFile(fakeEntryFileInfo, true))
                            {
                                return true;
                            };
                        }
                    }
                    // handle more complex ones here:
                    else if (classifier.MatchAction == MatchAction.Relay)
                    {
                        // TODO remove this 
                        UnpackToDisk = true;
                        if (UnpackToDisk)
                        {
                            string fileUnpackPathString =
                                UnpackPath + "\\" + archiveFilePath.Replace("\\\\", "").Replace(':','.') + "\\";
                            string fileUnpackPath = Path.GetFullPath(fileUnpackPathString);
                            // check the first level here:
                            FileClassifier fileClassifier = new FileClassifier(classifier);
                            if (fileClassifier.ClassifyFile(fakeEntryFileInfo, true))
                            {
                                // then figure out the next rule and build the classifier
                                try
                                {
                                    ClassifierRule nextRule =
                                        MyOptions.ClassifierRules.First(thing =>
                                            thing.RuleName == classifier.RelayTarget);
                                    // then if it's a contents one
                                    if (nextRule.EnumerationScope == EnumerationScope.ContentsEnumeration)
                                    {
                                        // extract the file to disk
                                        try
                                        {
                                            if (!Directory.Exists(Path.GetDirectoryName(fileUnpackPath)))
                                            {
                                                Directory.CreateDirectory(Path.GetDirectoryName(fileUnpackPath));
                                            }
                                            using (Stream stream = File.OpenRead(archiveFilePath))
                                            using (var reader = ReaderFactory.Open(stream))
                                            {
                                                while (reader.MoveToNextEntry())
                                                {
                                                    if (!reader.Entry.IsDirectory)
                                                    {
                                                        if (reader.Entry.Key == entryFile)
                                                        {
                                                            if (!File.Exists(Path.Combine(fileUnpackPath, entryFile)))
                                                            {
                                                                reader.WriteEntryToDirectory(fileUnpackPath,
                                                                    new ExtractionOptions()
                                                                    {
                                                                        ExtractFullPath = true,
                                                                        Overwrite = false
                                                                    });
                                                            }

                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        catch (System.IO.IOException e)
                                        {
                                            Mq.Error(e.ToString());
                                            // probably fine?
                                        }
                                        catch (System.UnauthorizedAccessException e)
                                        {
                                            Mq.Error(e.ToString());
                                        }
                                        catch (SharpCompress.Common.CryptographicException e)
                                        {
                                            Mq.FileResult(new FileResult(new FileInfo(archiveFilePath))
                                            {
                                                MatchedRule = new ClassifierRule() { Triage = Triage.Red, RuleName = "EncryptedArchive" }
                                            });
                                        }
                                        catch (System.ArgumentNullException e)
                                        {
                                            Mq.FileResult(new FileResult(new FileInfo(archiveFilePath))
                                            {
                                                MatchedRule = new ClassifierRule() { Triage = Triage.Red, RuleName = "EncryptedArchive" }
                                            });
                                        }
                                        catch (Exception e)
                                        {
                                            Mq.Error(e.ToString());
                                        }

                                        // make a new FileInfo for it.
                                        FileInfo extractedFileInfo =
                                            new FileInfo(Path.GetFullPath(Path.Combine(fileUnpackPath, entryFile)));
                                        ContentClassifier nextContentClassifier = new ContentClassifier(nextRule);
                                        if (nextContentClassifier.ClassifyContent(extractedFileInfo, archiveFilePath))
                                        {
                                            // clean up the file either way
                                            try
                                            {
                                                File.Delete(Path.GetFullPath(Path.Combine(fileUnpackPath, entryFile)));
                                            }
                                            catch (Exception e)
                                            {
                                                Mq.Error(e.ToString());
                                            }
                                            return true;
                                        }
                                        else
                                        {
                                            try
                                            {
                                                File.Delete(Path.GetFullPath(Path.Combine(fileUnpackPath, entryFile)));
                                            }
                                            catch (Exception e)
                                            {
                                                Mq.Error(e.ToString());
                                            }
                                        }
                                    }
                                    else
                                    {
                                        Mq.Error("You've got a misconfigured file ClassifierRule named " +
                                                 classifier.RuleName +
                                                 ". Archive rule chains may only be two levels, one with EnumerationScope.FileEnumeration, one with EnumerationScope.ContentsEnumeration.");
                                        return false;
                                    }
                                }
                                catch (IOException e)
                                {
                                    Mq.Error(e.ToString());
                                }
                                catch (Exception e)
                                {
                                    Mq.Error("You've got a misconfigured file ClassifierRule named " +
                                             classifier.RuleName + ".");
                                    Mq.Trace(e.ToString());
                                }

                                return false;
                            }

                            ;
                        }
                    }
                }
            }
            catch (FileNotFoundException e)
            {
                // If file was deleted by a separate application
                //  or thread since the call to TraverseTree()
                // then just continue.
                Mq.Trace(e.ToString());
                return false;
            }
            catch (UnauthorizedAccessException e)
            {
                Mq.Trace(e.ToString());
                return false;
            }
            catch (PathTooLongException)
            {
                Mq.Trace(fakeEntryFileInfo.FullName + " path was too long for me to look at.");
                return false;
            }
            catch (Exception e)
            {
                Mq.Trace(e.ToString());
                return false;
            }

            return false;
        }
        /*
            if (entry.Key == "[Content_Types].xml")
    {
        try
        {
            MemoryStream stream = new MemoryStream();
            entry.WriteTo(stream);

            byte[] bytes = stream.ToArray();

            string entryContents = Encoding.ASCII.GetString(bytes);

*/

        // ideally we want to:
        // open an archive
        // see if it's encrypted
        // report on that
        // see if there are files we like
        // keep them if we like them off the name alone
        // if we're relaying, extract the ones we like to a temp dir
        // do the next step there?

    }
}
