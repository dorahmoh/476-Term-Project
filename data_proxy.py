# utils/data_proxy.py
class SensitiveDataProxy:
    def __init__(self, data):
        self._data = data
        self._masked = True

    def get_data(self):
        if self._masked:
            return self._mask_data()
        else:
            return self._data

    def toggle_mask(self):
        self._masked = not self._masked

    def _mask_data(self):
        return '*' * len(self._data)  # Replace all characters with asterisks
