using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Data;
using System.Threading;

namespace _3PT
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        Task detourSendTask;
        public MainWindow()
        {
            InitializeComponent();
            detourSendTask = Detours.DetourWs2Send();

            detourSendTask.Start();
           
            PacketDataGrid.DataContext = Detours.packetTable.DefaultView;
            int me = 5;

        }


        private void Header_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if(e.ChangedButton == MouseButton.Left)
                DragMove();
        }

        private void StartStopToggleButton_Click(object sender, RoutedEventArgs e)
        {

        }

        private void ExitButton_Click(object sender, RoutedEventArgs e)
        {
            Hide();
            Detours.W32Send.detour = false;
            Task.WaitAll(detourSendTask);
            Environment.Exit(0);
        }

        private void MinimizeButton_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }
    }

}
