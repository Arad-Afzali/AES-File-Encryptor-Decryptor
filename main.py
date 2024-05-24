import generatekey
import encrypt
import decrypt
import newgui

if __name__ == "__main__":
    import tkinter as tk
    
    root = tk.Tk()
    app = newgui.AESApp(root)
    root.mainloop()
