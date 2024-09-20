using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpPcapDemo.Utilities
{
    internal class AsyncTask : IDisposable
    {
        public Task? Task { get; set; }
        public PeriodicTimer Timer { get; set; }
        public CancellationTokenSource CancelToken { get; set; }
        /// <summary>
        /// use this to create a seperate thread
        /// </summary>
        /// <param name="seconds">how often to run this task</param>
        public AsyncTask(int seconds)
        {
            Task = null;
            Timer = new PeriodicTimer(TimeSpan.FromSeconds(seconds));
            CancelToken = new CancellationTokenSource();
        }

        private async void StopProcess()
        {
            try
            {
                if (Task is null)
                {
                    return;
                }

                CancelToken.Cancel();
                Task = null;
                CancelToken.Dispose();
                Debug.WriteLine("Operation Cancelled");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"error: {ex.Message}");
            }
        }

        public void Dispose()
        {
            StopProcess();
        }
    }
}
