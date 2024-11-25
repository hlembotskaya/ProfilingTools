using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;

namespace MyCalculatorv1;

public partial class MainWindow : Window, IComponentConnector
{
	public MainWindow()
	{
		InitializeComponent();
	}

	private void Button_Click_1(object sender, RoutedEventArgs e)
	{
		Button button = (Button)sender;
		tb.Text += button.Content.ToString();
	}

	private void Result_click(object sender, RoutedEventArgs e)
	{
		result();
	}

	private void result()
	{
		int num = 0;
		if (tb.Text.Contains("+"))
		{
			num = tb.Text.IndexOf("+");
		}
		else if (tb.Text.Contains("-"))
		{
			num = tb.Text.IndexOf("-");
		}
		else if (tb.Text.Contains("*"))
		{
			num = tb.Text.IndexOf("*");
		}
		else if (tb.Text.Contains("/"))
		{
			num = tb.Text.IndexOf("/");
		}
		string text = tb.Text.Substring(num, 1);
		double num2 = Convert.ToDouble(tb.Text.Substring(0, num));
		double num3 = Convert.ToDouble(tb.Text.Substring(num + 1, tb.Text.Length - num - 1));
		switch (text)
		{
		case "+":
		{
			TextBox textBox = tb;
			textBox.Text = textBox.Text + "=" + (num2 + num3);
			break;
		}
		case "-":
		{
			TextBox textBox = tb;
			textBox.Text = textBox.Text + "=" + (num2 - num3);
			break;
		}
		case "*":
		{
			TextBox textBox = tb;
			textBox.Text = textBox.Text + "=" + num2 * num3;
			break;
		}
		default:
		{
			TextBox textBox = tb;
			textBox.Text = textBox.Text + "=" + num2 / num3;
			break;
		}
		}
	}

	private void Off_Click_1(object sender, RoutedEventArgs e)
	{
		Application.Current.Shutdown();
	}

	private void Del_Click(object sender, RoutedEventArgs e)
	{
		tb.Text = "";
	}

	private void R_Click(object sender, RoutedEventArgs e)
	{
		if (tb.Text.Length > 0)
		{
			tb.Text = tb.Text.Substring(0, tb.Text.Length - 1);
		}
	}
}
