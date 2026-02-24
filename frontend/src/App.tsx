import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import Layout from './components/Layout';
import Monitor from './pages/Monitor';
import Assets from './pages/Assets';
import RiskScanner from './pages/RiskScanner';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 5000,
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<Monitor />} />
            <Route path="/monitor" element={<Monitor />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/risk-scanner" element={<RiskScanner />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
