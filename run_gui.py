"""
Guvenli Dosya Transfer Sistemi - Grafiksel Arayuz

Bu script, uygulamanin grafiksel arayuzunu baslatir.
"""

import sys
from PyQt5.QtWidgets import QApplication
from src.gui.main_window import MainWindow

def main():
    # Uygulama nesnesini olustur
    app = QApplication(sys.argv)
    
    # Ana pencereyi olustur ve goster
    window = MainWindow()
    window.show()
    
    # Uygulama dongusunu baslat
    sys.exit(app.exec_())

if __name__ == "__main__":
    main() 