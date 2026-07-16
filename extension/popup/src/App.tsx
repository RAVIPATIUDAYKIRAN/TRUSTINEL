
function App() {
  return (
    <div className="flex flex-col min-h-[400px] w-[360px] bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-white font-sans overflow-hidden border border-slate-800 rounded-lg shadow-2xl relative">
      
      {/* Decorative Blur Orbs */}
      <div className="absolute -top-10 -left-10 w-24 h-24 bg-blue-500/10 rounded-full blur-xl pointer-events-none"></div>
      <div className="absolute -bottom-10 -right-10 w-24 h-24 bg-emerald-500/10 rounded-full blur-xl pointer-events-none"></div>

      {/* Header */}
      <header className="flex items-center justify-between px-5 py-4 border-b border-slate-800/80 bg-slate-900/40 backdrop-blur-md z-10">
        <div className="flex items-center gap-2">
          {/* Logo Icon */}
          <div className="h-7 w-7 rounded-lg bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-blue-500/20">
            <span className="text-xs font-black tracking-wider text-white">T</span>
          </div>
          <span className="text-sm font-extrabold tracking-widest bg-gradient-to-r from-blue-400 via-indigo-400 to-teal-400 bg-clip-text text-transparent">
            TRUSTINEL
          </span>
        </div>
        <div className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></span>
          <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-widest">Active</span>
        </div>
      </header>

      {/* Main Body */}
      <main className="flex-1 flex flex-col justify-center items-center px-6 py-8 text-center z-10">
        
        {/* Sprint Badge */}
        <div className="mb-6 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/30 shadow-inner flex items-center gap-1.5 animate-bounce">
          <span className="h-1.5 w-1.5 rounded-full bg-blue-400"></span>
          <span className="text-xs font-bold text-blue-400 uppercase tracking-widest">Sprint 1 Foundation</span>
        </div>

        {/* Dynamic Coming Soon Graphic */}
        <div className="relative mb-6">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-blue-500 to-indigo-600 flex items-center justify-center shadow-xl shadow-blue-500/25 relative group-hover:scale-105 transition-transform duration-300">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-8 w-8 text-white animate-pulse" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
        </div>

        {/* Header Text */}
        <h2 className="text-2xl font-black text-slate-100 tracking-tight leading-snug">
          Real-Time Verification
        </h2>
        <p className="mt-2 text-sm text-slate-400 max-w-[260px]">
          Deploying trust guardrails for safe, transparent web navigation.
        </p>

        {/* Coming Soon Announcement Card */}
        <div className="mt-6 w-full p-4 rounded-xl bg-slate-900/60 border border-slate-800/60 backdrop-blur-sm shadow-lg flex flex-col items-center">
          <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Project Status</span>
          <span className="mt-1 text-base font-extrabold text-teal-400 tracking-wide uppercase">Coming Soon</span>
        </div>

      </main>

      {/* Footer */}
      <footer className="px-5 py-3 border-t border-slate-800/80 bg-slate-900/40 backdrop-blur-md text-center z-10">
        <span className="text-[10px] font-medium text-slate-500 tracking-wider">
          v0.1.0 &copy; 2026 TRUSTINEL Corp
        </span>
      </footer>

    </div>
  );
}

export default App;
