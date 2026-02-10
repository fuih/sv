import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

// Types
interface VaultStatus {
  initialized: boolean;
  unlocked: boolean;
}

interface PasswordEntry {
  id: number;
  site_name: string;
  site_url: string;
  username: string;
  password: string;
  notes: string;
  created_at: string;
  updated_at: string;
}

interface GeneratedPassword {
  password: string;
  strength: string;
  entropy: number;
}

interface CommandResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

// Icons as SVG components
const ShieldIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);

const EyeIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="20" height="20">
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
    <circle cx="12" cy="12" r="3" />
  </svg>
);

const EyeOffIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="20" height="20">
    <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24" />
    <line x1="1" y1="1" x2="23" y2="23" />
  </svg>
);

const CopyIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="16" height="16">
    <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
    <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
  </svg>
);

const PlusIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="20" height="20">
    <line x1="12" y1="5" x2="12" y2="19" />
    <line x1="5" y1="12" x2="19" y2="12" />
  </svg>
);

const RefreshIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="16" height="16">
    <path d="M23 4v6h-6M1 20v-6h6" />
    <path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15" />
  </svg>
);

const LockIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="20" height="20">
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
    <path d="M7 11V7a5 5 0 0110 0v4" />
  </svg>
);

const TrashIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="16" height="16">
    <polyline points="3 6 5 6 21 6" />
    <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
  </svg>
);

const CloseIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="20" height="20">
    <line x1="18" y1="6" x2="6" y2="18" />
    <line x1="6" y1="6" x2="18" y2="18" />
  </svg>
);

const SearchIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="18" height="18">
    <circle cx="11" cy="11" r="8" />
    <line x1="21" y1="21" x2="16.65" y2="16.65" />
  </svg>
);

const KeyIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="18" height="18">
    <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
  </svg>
);

// App component
function App() {
  const [vaultStatus, setVaultStatus] = useState<VaultStatus | null>(null);
  const [masterPassword, setMasterPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [passwords, setPasswords] = useState<PasswordEntry[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [showAddModal, setShowAddModal] = useState(false);
  const [showGeneratorModal, setShowGeneratorModal] = useState(false);
  const [selectedEntry, setSelectedEntry] = useState<PasswordEntry | null>(null);
  const [visiblePasswords, setVisiblePasswords] = useState<Set<number>>(new Set());

  // Initialize vault on mount
  useEffect(() => {
    initVault();
  }, []);

  const initVault = async () => {
    try {
      const response = await invoke<CommandResponse<VaultStatus>>("init_vault");
      if (response.success && response.data) {
        setVaultStatus(response.data);
        if (response.data.unlocked) {
          await loadPasswords();
        }
      }
    } catch (err) {
      setError("Failed to initialize vault");
    } finally {
      setLoading(false);
    }
  };

  const loadPasswords = async () => {
    try {
      const response = await invoke<CommandResponse<PasswordEntry[]>>("get_passwords");
      if (response.success && response.data) {
        setPasswords(response.data);
      }
    } catch (err) {
      console.error("Failed to load passwords:", err);
    }
  };

  const handleSetup = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (masterPassword.length < 8) {
      setError("Master password must be at least 8 characters");
      return;
    }

    if (masterPassword !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }

    try {
      setLoading(true);
      const response = await invoke<CommandResponse<boolean>>("setup_vault", {
        masterPassword,
      });
      if (response.success) {
        setVaultStatus({ initialized: true, unlocked: true });
        setMasterPassword("");
        setConfirmPassword("");
      } else {
        setError(response.error || "Setup failed");
      }
    } catch (err) {
      setError("Failed to setup vault");
    } finally {
      setLoading(false);
    }
  };

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    try {
      setLoading(true);
      const response = await invoke<CommandResponse<boolean>>("unlock_vault", {
        masterPassword,
      });
      if (response.success) {
        setVaultStatus({ initialized: true, unlocked: true });
        setMasterPassword("");
        await loadPasswords();
      } else {
        setError(response.error || "Invalid password");
      }
    } catch (err) {
      setError("Failed to unlock vault");
    } finally {
      setLoading(false);
    }
  };

  const handleLock = async () => {
    try {
      await invoke("lock_vault");
      setVaultStatus({ initialized: true, unlocked: false });
      setPasswords([]);
      setVisiblePasswords(new Set());
    } catch (err) {
      console.error("Failed to lock vault:", err);
    }
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };

  const togglePasswordVisibility = (id: number) => {
    setVisiblePasswords(prev => {
      const newSet = new Set(prev);
      if (newSet.has(id)) {
        newSet.delete(id);
      } else {
        newSet.add(id);
      }
      return newSet;
    });
  };

  const handleDeletePassword = async (id: number) => {
    if (!confirm("Are you sure you want to delete this password?")) return;

    try {
      const response = await invoke<CommandResponse<boolean>>("delete_password", { id });
      if (response.success) {
        await loadPasswords();
      }
    } catch (err) {
      console.error("Failed to delete password:", err);
    }
  };

  const filteredPasswords = passwords.filter(
    (p) =>
      p.site_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.site_url.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.username.toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Loading screen
  if (loading && !vaultStatus) {
    return (
      <div className="auth-container">
        <div className="loading">
          <div className="spinner"></div>
        </div>
      </div>
    );
  }

  // Setup screen
  if (vaultStatus && !vaultStatus.initialized) {
    return (
      <div className="auth-container">
        <div className="auth-card fade-in">
          <div className="auth-logo">
            <ShieldIcon />
            <h1>SecureVault</h1>
          </div>
          <p className="auth-subtitle">
            Create a master password to protect your vault
          </p>

          {error && <div className="error-message">{error}</div>}

          <form onSubmit={handleSetup}>
            <div className="form-group">
              <label className="form-label">Master Password</label>
              <div className="password-input-wrapper">
                <input
                  type={showPassword ? "text" : "password"}
                  className="form-input"
                  placeholder="Enter master password"
                  value={masterPassword}
                  onChange={(e) => setMasterPassword(e.target.value)}
                  required
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? <EyeOffIcon /> : <EyeIcon />}
                </button>
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">Confirm Password</label>
              <input
                type="password"
                className="form-input"
                placeholder="Confirm master password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
              />
            </div>

            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? "Creating..." : "Create Vault"}
            </button>
          </form>
        </div>
      </div>
    );
  }

  // Unlock screen
  if (vaultStatus && !vaultStatus.unlocked) {
    return (
      <div className="auth-container">
        <div className="auth-card fade-in">
          <div className="auth-logo">
            <ShieldIcon />
            <h1>SecureVault</h1>
          </div>
          <p className="auth-subtitle">Enter your master password to unlock</p>

          {error && <div className="error-message">{error}</div>}

          <form onSubmit={handleUnlock}>
            <div className="form-group">
              <label className="form-label">Master Password</label>
              <div className="password-input-wrapper">
                <input
                  type={showPassword ? "text" : "password"}
                  className="form-input"
                  placeholder="Enter master password"
                  value={masterPassword}
                  onChange={(e) => setMasterPassword(e.target.value)}
                  required
                  autoFocus
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? <EyeOffIcon /> : <EyeIcon />}
                </button>
              </div>
            </div>

            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? "Unlocking..." : "Unlock"}
            </button>
          </form>
        </div>
      </div>
    );
  }

  // Main vault view
  return (
    <div className="app-layout">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <span className="sidebar-logo">🔐 SecureVault</span>
        </div>

        <div className="search-box">
          <span className="search-icon"><SearchIcon /></span>
          <input
            type="text"
            className="search-input"
            placeholder="Search passwords..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <nav className="sidebar-nav">
          <div className="nav-item active">
            <KeyIcon />
            <span className="nav-text">All Passwords</span>
          </div>
        </nav>

        <div className="sidebar-footer">
          <button className="btn btn-ghost" onClick={handleLock} style={{ width: '100%' }}>
            <LockIcon />
            <span className="nav-text">Lock Vault</span>
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="main-content">
        <header className="header">
          <h2>All Passwords</h2>
          <div className="header-actions">
            <button className="btn btn-secondary" onClick={() => setShowGeneratorModal(true)}>
              <RefreshIcon /> Generate
            </button>
            <button className="btn btn-primary" onClick={() => { setSelectedEntry(null); setShowAddModal(true); }}>
              <PlusIcon /> Add Password
            </button>
          </div>
        </header>

        {filteredPasswords.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">🔑</div>
            <h3 className="empty-title">No passwords yet</h3>
            <p className="empty-description">
              Add your first password to start building your secure vault
            </p>
            <button className="btn btn-primary" onClick={() => setShowAddModal(true)}>
              <PlusIcon /> Add Password
            </button>
          </div>
        ) : (
          <div className="password-grid">
            {filteredPasswords.map((entry) => (
              <div key={entry.id} className="password-card fade-in">
                <div className="card-header">
                  <div className="card-icon">
                    {entry.site_name.charAt(0).toUpperCase()}
                  </div>
                  <div>
                    <div className="card-title">{entry.site_name}</div>
                    <div className="card-url">{entry.site_url}</div>
                  </div>
                </div>

                <div className="card-body">
                  <div className="card-field">
                    <div>
                      <div className="field-label">Username</div>
                      <div className="field-value">{entry.username}</div>
                    </div>
                    <button className="btn btn-icon" onClick={() => copyToClipboard(entry.username)}>
                      <CopyIcon />
                    </button>
                  </div>

                  <div className="card-field">
                    <div>
                      <div className="field-label">Password</div>
                      <div className="field-value">
                        {visiblePasswords.has(entry.id) ? entry.password : "••••••••••••"}
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: '4px' }}>
                      <button className="btn btn-icon" onClick={() => togglePasswordVisibility(entry.id)}>
                        {visiblePasswords.has(entry.id) ? <EyeOffIcon /> : <EyeIcon />}
                      </button>
                      <button className="btn btn-icon" onClick={() => copyToClipboard(entry.password)}>
                        <CopyIcon />
                      </button>
                    </div>
                  </div>
                </div>

                <div className="card-actions">
                  <button className="btn btn-secondary" style={{ flex: 1 }} onClick={() => { setSelectedEntry(entry); setShowAddModal(true); }}>
                    Edit
                  </button>
                  <button className="btn btn-icon" onClick={() => handleDeletePassword(entry.id)}>
                    <TrashIcon />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </main>

      {/* Add/Edit Modal */}
      {showAddModal && (
        <AddPasswordModal
          entry={selectedEntry}
          onClose={() => { setShowAddModal(false); setSelectedEntry(null); }}
          onSave={async () => { await loadPasswords(); setShowAddModal(false); setSelectedEntry(null); }}
        />
      )}

      {/* Generator Modal */}
      {showGeneratorModal && (
        <GeneratorModal onClose={() => setShowGeneratorModal(false)} />
      )}
    </div>
  );
}

// Add/Edit Password Modal
function AddPasswordModal({
  entry,
  onClose,
  onSave,
}: {
  entry: PasswordEntry | null;
  onClose: () => void;
  onSave: () => void;
}) {
  const [siteName, setSiteName] = useState(entry?.site_name || "");
  const [siteUrl, setSiteUrl] = useState(entry?.site_url || "");
  const [username, setUsername] = useState(entry?.username || "");
  const [password, setPassword] = useState(entry?.password || "");
  const [notes, setNotes] = useState(entry?.notes || "");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const generatePassword = async () => {
    try {
      const response = await invoke<CommandResponse<GeneratedPassword>>("generate_password", {
        length: 24,
        lowercase: true,
        uppercase: true,
        digits: true,
        special: true,
        excludeAmbiguous: true,
      });
      if (response.success && response.data) {
        setPassword(response.data.password);
        setShowPassword(true);
      }
    } catch (err) {
      console.error("Failed to generate password:", err);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      if (entry) {
        // Update
        const response = await invoke<CommandResponse<boolean>>("update_password", {
          id: entry.id,
          siteName,
          siteUrl,
          username,
          password,
          notes,
        });
        if (!response.success) {
          setError(response.error || "Failed to update");
          return;
        }
      } else {
        // Add new
        const response = await invoke<CommandResponse<number>>("add_password", {
          siteName,
          siteUrl,
          username,
          password,
          notes,
        });
        if (!response.success) {
          setError(response.error || "Failed to add");
          return;
        }
      }
      onSave();
    } catch (err) {
      setError("Operation failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal fade-in" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3>{entry ? "Edit Password" : "Add Password"}</h3>
          <button className="btn btn-icon" onClick={onClose}>
            <CloseIcon />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="modal-body">
            {error && <div className="error-message">{error}</div>}

            <div className="form-group">
              <label className="form-label">Site Name</label>
              <input
                type="text"
                className="form-input"
                placeholder="e.g., GitHub"
                value={siteName}
                onChange={(e) => setSiteName(e.target.value)}
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">Website URL</label>
              <input
                type="text"
                className="form-input"
                placeholder="e.g., https://github.com"
                value={siteUrl}
                onChange={(e) => setSiteUrl(e.target.value)}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Username / Email</label>
              <input
                type="text"
                className="form-input"
                placeholder="Enter username or email"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">Password</label>
              <div className="password-input-wrapper">
                <input
                  type={showPassword ? "text" : "password"}
                  className="form-input"
                  placeholder="Enter password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? <EyeOffIcon /> : <EyeIcon />}
                </button>
              </div>
              <button
                type="button"
                className="btn btn-ghost"
                style={{ marginTop: "8px" }}
                onClick={generatePassword}
              >
                <RefreshIcon /> Generate Strong Password
              </button>
            </div>

            <div className="form-group">
              <label className="form-label">Notes (Optional)</label>
              <input
                type="text"
                className="form-input"
                placeholder="Add notes..."
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
              />
            </div>
          </div>

          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? "Saving..." : entry ? "Update" : "Save"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// Password Generator Modal
function GeneratorModal({ onClose }: { onClose: () => void }) {
  const [password, setPassword] = useState("");
  const [strength, setStrength] = useState("");
  const [entropy, setEntropy] = useState(0);
  const [length, setLength] = useState(24);
  const [lowercase, setLowercase] = useState(true);
  const [uppercase, setUppercase] = useState(true);
  const [digits, setDigits] = useState(true);
  const [special, setSpecial] = useState(true);
  const [excludeAmbiguous, setExcludeAmbiguous] = useState(true);

  const generate = useCallback(async () => {
    try {
      const response = await invoke<CommandResponse<GeneratedPassword>>("generate_password", {
        length,
        lowercase,
        uppercase,
        digits,
        special,
        excludeAmbiguous,
      });
      if (response.success && response.data) {
        setPassword(response.data.password);
        setStrength(response.data.strength);
        setEntropy(response.data.entropy);
      }
    } catch (err) {
      console.error("Failed to generate password:", err);
    }
  }, [length, lowercase, uppercase, digits, special, excludeAmbiguous]);

  useEffect(() => {
    generate();
  }, [generate]);

  const getStrengthClass = (s: string) => {
    switch (s) {
      case "Weak": return "weak";
      case "Fair": return "fair";
      case "Strong": return "strong";
      case "VeryStrong": return "very-strong";
      default: return "weak";
    }
  };

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(password);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal fade-in" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3>Password Generator</h3>
          <button className="btn btn-icon" onClick={onClose}>
            <CloseIcon />
          </button>
        </div>

        <div className="modal-body">
          <div className="generator-section">
            <div className="generator-preview">
              {password}
            </div>

            <div className="strength-indicator">
              <div className="strength-bar">
                <div className={`strength-fill ${getStrengthClass(strength)}`}></div>
              </div>
              <div className="strength-text">
                Strength: {strength} • Entropy: {entropy.toFixed(1)} bits
              </div>
            </div>
          </div>

          <div className="length-slider">
            <div className="length-header">
              <span className="option-label">Length</span>
              <span className="length-value">{length}</span>
            </div>
            <input
              type="range"
              className="slider"
              min="8"
              max="64"
              value={length}
              onChange={(e) => setLength(Number(e.target.value))}
            />
          </div>

          <div className="generator-options" style={{ marginTop: "20px" }}>
            <label className="option-item">
              <input
                type="checkbox"
                className="option-checkbox"
                checked={lowercase}
                onChange={(e) => setLowercase(e.target.checked)}
              />
              <span className="option-label">Lowercase (a-z)</span>
            </label>
            <label className="option-item">
              <input
                type="checkbox"
                className="option-checkbox"
                checked={uppercase}
                onChange={(e) => setUppercase(e.target.checked)}
              />
              <span className="option-label">Uppercase (A-Z)</span>
            </label>
            <label className="option-item">
              <input
                type="checkbox"
                className="option-checkbox"
                checked={digits}
                onChange={(e) => setDigits(e.target.checked)}
              />
              <span className="option-label">Digits (0-9)</span>
            </label>
            <label className="option-item">
              <input
                type="checkbox"
                className="option-checkbox"
                checked={special}
                onChange={(e) => setSpecial(e.target.checked)}
              />
              <span className="option-label">Special (!@#$)</span>
            </label>
            <label className="option-item">
              <input
                type="checkbox"
                className="option-checkbox"
                checked={excludeAmbiguous}
                onChange={(e) => setExcludeAmbiguous(e.target.checked)}
              />
              <span className="option-label">Exclude Similar</span>
            </label>
          </div>
        </div>

        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={generate}>
            <RefreshIcon /> Regenerate
          </button>
          <button className="btn btn-primary" onClick={copyToClipboard}>
            <CopyIcon /> Copy Password
          </button>
        </div>
      </div>
    </div>
  );
}

export default App;
