import tkinter as tk
from tkinter import messagebox
import nmap

def list_network_hosts(network):
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')

    result_text.delete(1.0, tk.END)  # effacer le texte précédent

    result_text.insert(tk.END, "Liste des machines sur le réseau local:\n")
    for host in nm.all_hosts():
        result_text.insert(tk.END, f"- {host}  ")
        # des informations sur ip
        detail_button = tk.Button(fenetre, text="Détails", command=lambda ip=host: get_host_info(ip))
        result_text.window_create(tk.END, window=detail_button)

        result_text.insert(tk.END, "\n")

def get_host_info(ip_address):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_address, arguments='-O -p 1-1000')

    result_text.delete(1.0, tk.END)  # efface le texte precedent0

    result_text.insert(tk.END, f"Informations pour la machine {ip_address} :\n")
    for host in nm.all_hosts():
        result_text.insert(tk.END, f"   - Adresse IP: {host}\n")

        if 'mac' in nm[host]['addresses']:
            result_text.insert(tk.END, f"   - Adresse MAC: {nm[host]['addresses']['mac']}\n")
        else:
            result_text.insert(tk.END, "   - Adresse MAC: N/A\n")

        if 'osmatch' in nm[host]:
            result_text.insert(tk.END, f"   - Système d'exploitation: {nm[host]['osmatch'][0]['name']}\n")
        else:
            result_text.insert(tk.END, "   - Système d'exploitation: N/A\n")

        result_text.insert(tk.END, "   - Ports ouverts:\n")
        for proto in nm[host]['tcp'].keys():
            ports = nm[host]['tcp'][proto].keys()
            result_text.insert(tk.END, f"      - {proto}: {', '.join(ports)}\n")
def on_button_click(): #function pour le btn click valide
    selected_option = option_var.get() #recuper le radio 
    
    adresse_ip = saisi.get() #recuper ip
   
    if not adresse_ip:
        messagebox.showwarning("Avertissement", "Veuillez saisir une adresse IP.")   #si on ne entre pas de ip 
    else:
        if selected_option == 1:
            network = saisi_var.get() #recuper ip
            list_network_hosts(network) # liste les machine qui sont connecter sur le reseau
        elif selected_option == 2:
            adresse_ip = saisi_var.get() #recuper ip
            get_host_info(adresse_ip) #info sur host ou la machine
    
        else:
            messagebox.showwarning("Avertissement", "Option non valide.")


def apropos():
    messagebox.showinfo("À propos de l'application", "NetScan24\nVersion 1.06\nAuteur: GROUPE A")

if __name__ == "__main__":
    fenetre = tk.Tk() #creation fenetre
    fenetre.title("NetScan24") #titre de fenetre
    menu_bar = tk.Menu(fenetre)
    fenetre.config(menu=menu_bar)
    fenetre.minsize(525,400) #tailler de fenetre
    fenetre.maxsize(525,400) #tailler de fenetre
    file_menu = tk.Menu(menu_bar, tearoff=0)
    menu_bar.add_cascade(label="Menu", menu=file_menu)
    file_menu.add_command(label="À propos de l'application", command=lambda: messagebox.showinfo("À propos de l'application", "NetScan24\nVersion 1.07\nAuteur: GROUPE A"))
    file_menu.add_separator()
    file_menu.add_command(label="Quitter", command=fenetre.quit)

    option_var = tk.IntVar()
    option_var.set(1)

    label_option = tk.Label(fenetre, text="Choisissez une option:")
    label_option.grid(row=0, column=0, columnspan=2, pady=10)

    radio_option1 = tk.Radiobutton(fenetre, text="Lister toutes les machines sur le réseau local", variable=option_var, value=1)
    radio_option2 = tk.Radiobutton(fenetre, text="Obtenir des informations détaillées pour une machine specifique", variable=option_var, value=2)
    radio_option1.grid(row=1, column=0, sticky=tk.W, pady=5)
    radio_option2.grid(row=2, column=0, sticky=tk.W, pady=5)

    label_entry = tk.Label(fenetre, text="Entrez la plage d'adresses IP ou l'adresse IP:")
    label_entry.grid(row=3, column=0, columnspan=2, pady=5)

    saisi_var = tk.StringVar()
    saisi = tk.Entry(fenetre, textvariable=saisi_var, width=20)
    saisi.grid(row=4, column=0, columnspan=2, pady=5)

    button_scan = tk.Button(fenetre, text="Lancer", command=lambda: on_button_click())
    button_scan.grid(row=5, column=0, columnspan=2, pady=10)

    result_text = tk.Text(fenetre, height=10, width=60)
    result_text.grid(row=6, column=0, columnspan=2, pady=10, padx=15)

    fenetre.mainloop()
# pip install customtkinter pip install flet pip install pyinstaller