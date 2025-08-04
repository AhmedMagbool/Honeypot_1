 const ctx = document.getElementById('attackChart').getContext('2d');
  let currentView = 'perDay';
  let currentType = 'bar';
  let chart;

  function groupByDay(data) {
    const map = {};
    data.forEach(entry => {
      const date = new Date(entry.time).toISOString().split('T')[0];
      map[date] = (map[date] || 0) + 1;
    });
    return map;
  }

  function groupByIP(data) {
    const map = {};
    data.forEach(entry => {
      map[entry.ip] = (map[entry.ip] || 0) + 1;
    });
    return map;
  }

  function renderChart(groupedData, label) {
    const labels = Object.keys(groupedData);
    const values = Object.values(groupedData);

    if (chart) chart.destroy();

    chart = new Chart(ctx, {
      type: currentType,
      data: {
        labels,
        datasets: [{
          label,
          data: values,
          backgroundColor: 'rgba(255, 99, 132, 0.3)',
          borderColor: 'rgba(255, 99, 132, 1)',
          borderWidth: 3,
          fill: currentType === 'line',
          tension: 0.4,
          borderRadius: currentType === 'bar' ? 20 : 0,
          pointBackgroundColor: '#fff',
          pointRadius: currentType === 'line' ? 4 : 0
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: {
            labels: { color: '#fff' }
          }
        },
        scales: {
          x: {
            ticks: { color: '#fff' },
            grid: { color: '#333' }
          },
          y: {
            beginAtZero: true,
            ticks: { color: '#fff' },
            grid: { color: '#333' }
          }
        }
      }
    });
  }

  fetch('https://honeypot-715b9-default-rtdb.firebaseio.com/honeypot_logs.json')
    .then(res => res.json())
    .then(data => {
      const entries = Object.values(data);
      let grouped = groupByDay(entries);
      renderChart(grouped, 'Attacks per Day');

      document.getElementById('toggleChart').addEventListener('click', () => {
        currentType = currentType === 'bar' ? 'line' : 'bar';
        const grouped = currentView === 'perDay' ? groupByDay(entries) : groupByIP(entries);
        const label = currentView === 'perDay' ? 'Attacks per Day' : 'Attempts per IP';
        renderChart(grouped, label);
      });
    });