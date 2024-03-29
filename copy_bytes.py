# Stolen from @herrcore's GitHub, modified it so that you can copy a large block of bytes 
# usage: in the IDAPython bar on the bottom of IDA, copy_bytes(start_addr, length, 'filename')
# remeber to use '0x' if using hex values. filename needs quotes and will be saved in the same directory as the idb file.  

import os
import sys
import idc
import idaapi
import idautils
import binascii

major, minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = (major > 6)
using_pyqt5 = using_ida7api or (major == 6 and minor >= 9)

if using_pyqt5:
    import PyQt5.QtGui as QtGui
    import PyQt5.QtCore as QtCore
    import PyQt5.QtWidgets as QtWidgets
    from PyQt5.Qt import QApplication

else:
    import PySide.QtGui as QtGui
    import PySide.QtCore as QtCore
    QtWidgets = QtGui
    QtCore.pyqtSignal = QtCore.Signal
    QtCore.pyqtSlot = QtCore.Slot
    from PySide.QtGui import QApplication


def copy_to_clip(data):
    QApplication.clipboard().setText(data)


def copy_bytes(start, length, filepath):
    data = idc.get_bytes(start, length)
    copy_to_clip(data.hex())
    with open(filepath, 'wb') as outfile:
        outfile.write(data)
