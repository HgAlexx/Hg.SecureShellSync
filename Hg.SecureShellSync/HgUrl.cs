using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace HgSecureShellSync
{
    public partial class HgUrl : Form
    {
        public HgUrl()
        {
            InitializeComponent();
        }

        public void SetTitle(string value)
        {
            Text = value;
        }

        public void SetUrl(string value)
        {
            textBoxUrl.Text = value;
        }
        public string GetUrl()
        {
            return textBoxUrl.Text;
        }
    }
}
