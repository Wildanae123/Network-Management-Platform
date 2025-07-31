import React, { useState, useCallback } from "react";
import { CloudUpload, File, X, AlertTriangle } from "lucide-react";

// File Upload Component with enhanced requirements display
export const FileUploadComponent = ({
  onFileUpload,
  disabled,
  uploadedFile,
  onFileRemove,
}) => {
  const [dragActive, setDragActive] = useState(false);

  const handleDrag = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  }, []);

  const handleDrop = useCallback(
    (e) => {
      e.preventDefault();
      e.stopPropagation();
      setDragActive(false);

      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        onFileUpload(e.dataTransfer.files[0]);
      }
    },
    [onFileUpload]
  );

  const handleChange = useCallback(
    (e) => {
      e.preventDefault();
      if (e.target.files && e.target.files[0]) {
        onFileUpload(e.target.files[0]);
      }
    },
    [onFileUpload]
  );

  return (
    <div className="file-upload-container">
      {!uploadedFile ? (
        <>
          <div
            className={`file-upload-area ${dragActive ? "drag-active" : ""} ${
              disabled ? "disabled" : ""
            }`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
          >
            <input
              type="file"
              id="file-upload"
              accept=".csv"
              onChange={handleChange}
              disabled={disabled}
              className="file-input"
            />
            <label htmlFor="file-upload" className="file-upload-label">
              <CloudUpload size={48} className="upload-icon" />
              <div className="upload-text">
                <h4>Upload CSV File</h4>
                <p>
                  Drag and drop your device list CSV file here, or click to
                  browse
                </p>
                <small>Supported format: CSV files only</small>
              </div>
            </label>
          </div>
          <div className="upload-requirements">
            <h4>CSV Requirements:</h4>
            <ul>
              <li>
                <strong>Required:</strong> IP MGMT (IP address)
              </li>
            </ul>
          </div>
        </>
      ) : (
        <div className="uploaded-file-info">
          <div className="file-success">
            <File size={24} className="file-icon" />
            <div className="file-details">
              <h4>File Uploaded Successfully</h4>
              <p>{uploadedFile.name}</p>
              <small>{uploadedFile.deviceCount} devices found</small>
              {uploadedFile.detectedVendors &&
                uploadedFile.detectedVendors.length > 0 && (
                  <small className="detected-vendors">
                    Vendors: {uploadedFile.detectedVendors.join(", ")}
                  </small>
                )}
            </div>
            {onFileRemove && (
              <button
                className="remove-file-btn"
                onClick={onFileRemove}
                disabled={disabled}
                aria-label="Remove file"
              >
                <X size={16} />
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export const FileUploadComponentWithWarnings = ({
  onFileUpload,
  disabled,
  uploadedFile,
  onFileRemove,
}) => {
  return (
    <div className="file-upload-wrapper">
      <FileUploadComponent
        onFileUpload={onFileUpload}
        disabled={disabled}
        uploadedFile={uploadedFile}
        onFileRemove={onFileRemove}
      />
      {uploadedFile?.warnings && uploadedFile.warnings.length > 0 && (
        <div className="upload-warnings">
          <AlertTriangle size={16} />
          <span>{uploadedFile.warnings.length} warnings found in CSV</span>
        </div>
      )}
    </div>
  );
};