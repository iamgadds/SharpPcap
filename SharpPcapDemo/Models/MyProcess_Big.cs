using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpPcapDemo.Models
{
    public class MyProcess_Big
    {
        private string? name;
        public string? Name
        {
            get { return name; }
            set { name = value; OnPropertyChanged("Name"); }
        }

        private long currentdataRecv;
        public long CurrentDataRecv
        {
            get { return currentdataRecv; }
            set
            {
                if (currentdataRecv != value)
                {
                    currentdataRecv = value;
                    OnPropertyChanged("CurrentDataRecv");
                }
            }
        }

        private long currentdataSend;
        public long CurrentDataSend
        {
            get { return currentdataSend; }
            set
            {
                if (currentdataSend != value)
                {
                    currentdataSend = value;
                    OnPropertyChanged("CurrentDataSend");
                }
            }
        }

        private long totaldataRecv;
        public long TotalDataRecv
        {
            get { return totaldataRecv; }
            set
            {
                if (totaldataRecv != value)
                {
                    totaldataRecv = value;
                    OnPropertyChanged("TotalDataRecv");
                }
            }
        }

        private long totaldataSend;
        public long TotalDataSend
        {
            get { return totaldataSend; }
            set
            {
                if (totaldataSend != value)
                {
                    totaldataSend = value;
                    OnPropertyChanged("TotalDataSend");
                }
            }
        }

        public bool? IsSystemApp { get; set; }
        public int ProcessId { get; set; }

        public int Port { get; set; }

        public MyProcess_Big(string nameP, long currentDataRecvP, long currentDataSendP, long totalDataRecvP, long totalDataSendP)
        {
            Name = nameP;
            CurrentDataRecv = currentDataRecvP;
            CurrentDataSend = currentDataSendP;
            TotalDataRecv = totalDataRecvP;
            TotalDataSend = totalDataSendP;
        }

        public MyProcess_Big() { }

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged(string propName) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));
    }
}
