    const ADDRESS = 'bc1qrfagrsfrm8erdsmrku3fgq5yc573zyp2q3uje8';
    const BIP21_URI = 'bitcoin:' + ADDRESS;

    (function() {
      const matrix = QRGenerator.generateQR(BIP21_URI.toUpperCase(), QRGenerator.EC_M);
      const cellSize = 5;
      const margin = 4;
      const size = matrix.length;
      const canvas = document.getElementById('qrCode');
      const totalSize = (size + margin * 2) * cellSize;
      canvas.width = totalSize;
      canvas.height = totalSize;
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, totalSize, totalSize);
      ctx.fillStyle = '#000000';
      for (let row = 0; row < size; row++) {
        for (let col = 0; col < size; col++) {
          if (matrix[row][col]) {
            ctx.fillRect((col + margin) * cellSize, (row + margin) * cellSize, cellSize, cellSize);
          }
        }
      }
    })();

