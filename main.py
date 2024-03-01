import tkinter as tk
from tkinter import scrolledtext, messagebox
from threading import Thread
import socket

def scan_port(ip, port, output_area):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # Timeout ajustado para resposta rápida
            result = s.connect_ex((ip, port))
            if result == 0:
                output_area.insert(tk.END, f"Port: {port} is open\n")
    except Exception as e:
        output_area.insert(tk.END, f"Error scanning port {port}: {e}\n")

def start_scan(target, start_port, end_port, output_area, scan_button):
    # Desabilita o botão de escaneamento para evitar múltiplos cliques
    scan_button.config(state=tk.DISABLED)
    output_area.insert(tk.END, "Scanning started...\n")

    def runner():
        for port in range(start_port, end_port + 1):
            scan_port(target, port, output_area)
        output_area.insert(tk.END, "Scanning finished.\n")
        # Habilita o botão de escaneamento após a conclusão
        scan_button.config(state=tk.NORMAL)

    # Mostra uma mensagem indicando que o escaneamento começou
    messagebox.showinfo("Information", "Scanning started. This might take a while.")

    thread = Thread(target=runner)
    thread.start()

def create_gui():
    window = tk.Tk()
    window.title("Localhost Port Scanner")

    tk.Label(window, text="Target Host (e.g., localhost):").grid(row=0, column=0, sticky='w')
    target_entry = tk.Entry(window)
    target_entry.grid(row=0, column=1)
    target_entry.insert(0, "127.0.0.1")  # Default to localhost

    tk.Label(window, text="Start Port:").grid(row=1, column=0, sticky='w')
    start_port_entry = tk.Entry(window)
    start_port_entry.grid(row=1, column=1)
    start_port_entry.insert(0, "1")  # Default start port

    tk.Label(window, text="End Port:").grid(row=2, column=0, sticky='w')
    end_port_entry = tk.Entry(window)
    end_port_entry.grid(row=2, column=1)
    end_port_entry.insert(0, "65535")  # Default end port to scan all ports

    output_area = scrolledtext.ScrolledText(window, height=15, width=50)
    output_area.grid(row=4, column=0, columnspan=2, pady=10)

    scan_button = tk.Button(window, text="Start Scan", command=lambda: start_scan(
        target_entry.get(),
        int(start_port_entry.get()),
        int(end_port_entry.get()),
        output_area,
        scan_button
    ))
    scan_button.grid(row=3, column=0, columnspan=2)

    window.mainloop()

if __name__ == "__main__":
    create_gui()
