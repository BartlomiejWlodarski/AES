using System;
using System.IO;
using System.Text;
using System.Windows;
using Microsoft.Win32;

namespace AES
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly Aes aes = new();
        private byte[]? plainText;
        private byte[]? cipheredText;

        public MainWindow()
        {
            InitializeComponent();
            KeyTxt.Text = "4D635166546A576E5A72347537782141";
        }

        private void ShowErrorMessage(string message)
        {
            MessageBox.Show(message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }

        private void GenerateKeyBtn_Click(object sender, RoutedEventArgs e)
        {
            KeyTxt.Text = "";
            try
            {
                int keySize = GetKeySize();
                byte[] generatedKey = aes.GenerateKey(keySize);
                KeyTxt.Text = BitConverter.ToString(generatedKey).Replace("-", "");
            } catch (AESException ex) { ShowErrorMessage(ex.Message); }

        }

        private int GetKeySize()
        {
            if (Key128Radio.IsChecked == true)
            {
                return 128;
            }
            else if (Key192Radio.IsChecked == true)
            {
                return 192;
            }
            else if (Key256Radio.IsChecked == true)
            {
                return 256;
            }
            else throw new AESException("Select key size.");
        }

        private void EncryptBtn_Click(object sender, RoutedEventArgs e)
        {
            if (DecryptedTxt.Text == "")
            {
                ShowErrorMessage("Empty text to encrypt");
                return;
            }
            try
            {
                byte[] buffer = aes.Encrypt(Encoding.UTF8.GetBytes(DecryptedTxt.Text), Convert.FromHexString(KeyTxt.Text));
                EncryptedTxt.Text = BitConverter.ToString(buffer).Replace("-", "");
            }
            catch (Exception ex)
            {
                ShowErrorMessage(ex.Message);
            }
        }

        private void DecryptBtn_Click(object sender, RoutedEventArgs e)
        {
            if (EncryptedTxt.Text == "")
            {
                ShowErrorMessage("Empty text to decrypt");
                return;
            }
            try
            {
                byte[] buffer = aes.Decrypt(Convert.FromHexString(EncryptedTxt.Text), Convert.FromHexString(KeyTxt.Text));
                DecryptedTxt.Text = Encoding.UTF8.GetString(buffer);
            }
            catch (ArgumentException ex)
            {
                ShowErrorMessage(ex.Message);
            }
        }

        private void LoadDecryptedFileBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                OpenFileDialog openFileDialog = new OpenFileDialog();
                if (openFileDialog.ShowDialog() == true)
                {
                    plainText = File.ReadAllBytes(openFileDialog.FileName);
                    cipheredText = aes.Encrypt(plainText, Convert.FromHexString(KeyTxt.Text));
                    DecryptedTxt.Text = Encoding.UTF8.GetString(plainText);
                    EncryptedTxt.Text = BitConverter.ToString(cipheredText).Replace("-", "");
                    DecryptedFileLbl.Text = openFileDialog.FileName;
                }
            } catch (AESException ex)
            {
                ShowErrorMessage(ex.Message);
            } catch(Exception ex)
            {
                ShowErrorMessage(ex.Message);
            }

        }

        private void LoadEncryptedFileBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                OpenFileDialog openFileDialog = new OpenFileDialog();
                if (openFileDialog.ShowDialog() == true)
                {
                    cipheredText = File.ReadAllBytes(openFileDialog.FileName);
                    plainText = aes.Decrypt(cipheredText, Convert.FromHexString(KeyTxt.Text));
                    DecryptedTxt.Text = Encoding.UTF8.GetString(plainText);
                    EncryptedTxt.Text = BitConverter.ToString(cipheredText).Replace("-", "");
                    EncryptedFileLbl.Text = openFileDialog.FileName;
                }
            }
            catch (ArgumentException ex)
            {
                ShowErrorMessage(ex.Message);
            }
        }

        private void SaveDecryptedFileBtn_Click(object sender, RoutedEventArgs e)
        {
            if (plainText == null || plainText.Length == 0)
            {
                ShowErrorMessage("Nothing to save.");
                return;
            }
            SaveFileDialog saveFileDialog = new();
            if (saveFileDialog.ShowDialog() == true)
            {
                try
                {
                    File.WriteAllBytes(saveFileDialog.FileName, plainText);
                }
                catch
                {
                    ShowErrorMessage("Couldnt't save file.");
                }
            }
        }

        private void SaveEncryptedFileBtn_Click(object sender, RoutedEventArgs e)
        {
            if (cipheredText == null || cipheredText.Length == 0)
            {
                ShowErrorMessage("Nothing to save.");
                return;
            }
            SaveFileDialog saveFileDialog = new();
            if (saveFileDialog.ShowDialog() == true) {
                try
                {
                    File.WriteAllBytes(saveFileDialog.FileName, cipheredText);
                } catch
                {
                    ShowErrorMessage("Couldnt't save file.");
                }
            }
        }

        private void EmptyLeftBoxBtn_Click(object sender, RoutedEventArgs e)
        {
            DecryptedTxt.Text = "";
        }

        private void EmptyRightBoxBtn_Click(object sender, RoutedEventArgs e)
        {
            EncryptedTxt.Text = "";
        }
    }
}
