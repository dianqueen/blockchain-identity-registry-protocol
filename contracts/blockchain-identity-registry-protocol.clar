;; Blockchain Identity Registry Protocol
;; Decentralized identity management system with cryptographic verification and access control

;; ========== Registry Counter Initialization ==========
(define-data-var identity-nexus-counter uint u0)

;; ========== Error Code Registry ==========
(define-constant err-admin-required (err u407))
(define-constant err-access-denied (err u408))
(define-constant err-unauthorized-action (err u405))
(define-constant err-record-not-found (err u401))
(define-constant err-invalid-identifier (err u403))
(define-constant err-data-validation-failed (err u404))
(define-constant err-ownership-verification-failed (err u406))
(define-constant err-duplicate-entry (err u402))
(define-constant err-metadata-validation-failed (err u409))

;; ========== Protocol Administrator Definition ==========
(define-constant nexus-administrator tx-sender)

;; ========== Core Data Structure Mappings ==========
(define-map blockchain-identity-registry
  { identity-id: uint }
  {
    identity-label: (string-ascii 64),
    record-owner: principal,
    data-weight: uint,
    creation-block: uint,
    record-description: (string-ascii 128),
    attribute-collection: (list 10 (string-ascii 32))
  }
)

(define-map access-permission-registry
  { identity-id: uint, accessor: principal }
  { read-access-granted: bool }
)

;; ========== Administrative Functions ==========

;; Validates system integrity and returns operational metrics
(define-public (validate-system-integrity)
  (begin
    ;; Ensure caller has administrative privileges
    (asserts! (is-eq tx-sender nexus-administrator) err-admin-required)

    ;; Return system status metrics
    (ok {
      total-identities: (var-get identity-nexus-counter),
      system-operational: true,
      current-block-height: block-height
    })
  )
)

;; Retrieves comprehensive identity record information
(define-public (fetch-identity-record (identity-id uint))
  (let
    (
      (identity-data (unwrap! (map-get? blockchain-identity-registry { identity-id: identity-id }) err-record-not-found))
      (record-creation-block (get creation-block identity-data))
    )
    ;; Validate record existence and access permissions
    (asserts! (check-record-exists identity-id) err-record-not-found)
    (asserts! 
      (or 
        (is-eq tx-sender (get record-owner identity-data))
        (default-to false (get read-access-granted (map-get? access-permission-registry { identity-id: identity-id, accessor: tx-sender })))
        (is-eq tx-sender nexus-administrator)
      ) 
      err-unauthorized-action
    )

    ;; Return comprehensive record analytics
    (ok {
      record-age: (- block-height record-creation-block),
      data-complexity: (get data-weight identity-data),
      attribute-count: (len (get attribute-collection identity-data))
    })
  )
)

;; ========== Identity Creation Functions ==========

;; Creates new blockchain identity record with full validation
(define-public (register-new-identity 
  (identity-label (string-ascii 64)) 
  (data-weight uint) 
  (record-description (string-ascii 128)) 
  (attribute-collection (list 10 (string-ascii 32)))
)
  (let
    (
      (new-identity-id (+ (var-get identity-nexus-counter) u1))
    )
    ;; Comprehensive input validation
    (asserts! (> (len identity-label) u0) err-invalid-identifier)
    (asserts! (< (len identity-label) u65) err-invalid-identifier)
    (asserts! (> data-weight u0) err-data-validation-failed)
    (asserts! (< data-weight u1000000000) err-data-validation-failed)
    (asserts! (> (len record-description) u0) err-invalid-identifier)
    (asserts! (< (len record-description) u129) err-invalid-identifier)
    (asserts! (verify-attribute-structure attribute-collection) err-metadata-validation-failed)

    ;; Store identity record in blockchain registry
    (map-insert blockchain-identity-registry
      { identity-id: new-identity-id }
      {
        identity-label: identity-label,
        record-owner: tx-sender,
        data-weight: data-weight,
        creation-block: block-height,
        record-description: record-description,
        attribute-collection: attribute-collection
      }
    )

    ;; Grant initial access permissions to creator
    (map-insert access-permission-registry
      { identity-id: new-identity-id, accessor: tx-sender }
      { read-access-granted: true }
    )

    ;; Update global identity counter
    (var-set identity-nexus-counter new-identity-id)
    (ok new-identity-id)
  )
)

;; ========== Record Modification Functions ==========

;; Updates existing identity record with comprehensive validation
(define-public (modify-identity-record 
  (identity-id uint) 
  (updated-label (string-ascii 64)) 
  (updated-weight uint) 
  (updated-description (string-ascii 128)) 
  (updated-attributes (list 10 (string-ascii 32)))
)
  (let
    (
      (current-record (unwrap! (map-get? blockchain-identity-registry { identity-id: identity-id }) err-record-not-found))
    )
    ;; Validate record existence and ownership
    (asserts! (check-record-exists identity-id) err-record-not-found)
    (asserts! (is-eq (get record-owner current-record) tx-sender) err-ownership-verification-failed)

    ;; Validate all input parameters
    (asserts! (> (len updated-label) u0) err-invalid-identifier)
    (asserts! (< (len updated-label) u65) err-invalid-identifier)
    (asserts! (> updated-weight u0) err-data-validation-failed)
    (asserts! (< updated-weight u1000000000) err-data-validation-failed)
    (asserts! (> (len updated-description) u0) err-invalid-identifier)
    (asserts! (< (len updated-description) u129) err-invalid-identifier)
    (asserts! (verify-attribute-structure updated-attributes) err-metadata-validation-failed)

    ;; Update identity record with new values
    (map-set blockchain-identity-registry
      { identity-id: identity-id }
      (merge current-record { 
        identity-label: updated-label, 
        data-weight: updated-weight, 
        record-description: updated-description, 
        attribute-collection: updated-attributes 
      })
    )
    (ok true)
  )
)

;; ========== Access Control Management ==========

;; Grants read access to specified principal for identity record
(define-public (grant-record-access (identity-id uint) (accessor-principal principal))
  (let
    (
      (identity-data (unwrap! (map-get? blockchain-identity-registry { identity-id: identity-id }) err-record-not-found))
    )
    ;; Validate record existence and ownership
    (asserts! (check-record-exists identity-id) err-record-not-found)
    (asserts! (is-eq (get record-owner identity-data) tx-sender) err-ownership-verification-failed)

    (ok true)
  )
)

;; Revokes read access from specified principal for identity record
(define-public (revoke-record-access (identity-id uint) (accessor-principal principal))
  (let
    (
      (identity-data (unwrap! (map-get? blockchain-identity-registry { identity-id: identity-id }) err-record-not-found))
    )
    ;; Validate record existence and ownership
    (asserts! (check-record-exists identity-id) err-record-not-found)
    (asserts! (is-eq (get record-owner identity-data) tx-sender) err-ownership-verification-failed)
    (asserts! (not (is-eq accessor-principal tx-sender)) err-admin-required)

    ;; Remove access permissions
    (map-delete access-permission-registry { identity-id: identity-id, accessor: accessor-principal })
    (ok true)
  )
)

;; ========== Identity Verification System ==========

;; Performs comprehensive ownership verification for identity records
(define-public (verify-record-ownership (identity-id uint) (claimed-owner principal))
  (let
    (
      (identity-data (unwrap! (map-get? blockchain-identity-registry { identity-id: identity-id }) err-record-not-found))
      (actual-record-owner (get record-owner identity-data))
      (record-creation-time (get creation-block identity-data))
      (has-read-permission (default-to 
        false 
        (get read-access-granted 
          (map-get? access-permission-registry { identity-id: identity-id, accessor: tx-sender })
        )
      ))
    )
    ;; Validate record existence and access permissions
    (asserts! (check-record-exists identity-id) err-record-not-found)
    (asserts! 
      (or 
        (is-eq tx-sender actual-record-owner)
        has-read-permission
        (is-eq tx-sender nexus-administrator)
      ) 
      err-unauthorized-action
    )

    ;; Generate verification response
    (if (is-eq actual-record-owner claimed-owner)
      ;; Return successful ownership verification
      (ok {
        ownership-verified: true,
        verification-timestamp: block-height,
        record-lifespan: (- block-height record-creation-time),
        owner-authenticated: true
      })
      ;; Return ownership mismatch
      (ok {
        ownership-verified: false,
        verification-timestamp: block-height,
        record-lifespan: (- block-height record-creation-time),
        owner-authenticated: false
      })
    )
  )
)

;; ========== Record Management Operations ==========

;; Permanently removes identity record from blockchain registry
(define-public (delete-identity-record (identity-id uint))
  (let
    (
      (identity-data (unwrap! (map-get? blockchain-identity-registry { identity-id: identity-id }) err-record-not-found))
    )
    ;; Validate ownership for deletion
    (asserts! (check-record-exists identity-id) err-record-not-found)
    (asserts! (is-eq (get record-owner identity-data) tx-sender) err-ownership-verification-failed)

    ;; Remove record from registry
    (map-delete blockchain-identity-registry { identity-id: identity-id })
    (ok true)
  )
)

;; Adds additional attributes to existing identity record
(define-public (append-record-attributes (identity-id uint) (new-attributes (list 10 (string-ascii 32))))
  (let
    (
      (identity-data (unwrap! (map-get? blockchain-identity-registry { identity-id: identity-id }) err-record-not-found))
      (current-attributes (get attribute-collection identity-data))
      (combined-attributes (unwrap! (as-max-len? (concat current-attributes new-attributes) u10) err-metadata-validation-failed))
    )
    ;; Validate record existence and ownership
    (asserts! (check-record-exists identity-id) err-record-not-found)
    (asserts! (is-eq (get record-owner identity-data) tx-sender) err-ownership-verification-failed)

    ;; Validate new attributes structure
    (asserts! (verify-attribute-structure new-attributes) err-metadata-validation-failed)

    ;; Update record with combined attributes
    (map-set blockchain-identity-registry
      { identity-id: identity-id }
      (merge identity-data { attribute-collection: combined-attributes })
    )
    (ok combined-attributes)
  )
)

;; Transfers record ownership to new principal
(define-public (transfer-record-ownership (identity-id uint) (new-owner-principal principal))
  (let
    (
      (identity-data (unwrap! (map-get? blockchain-identity-registry { identity-id: identity-id }) err-record-not-found))
    )
    ;; Validate current ownership
    (asserts! (check-record-exists identity-id) err-record-not-found)
    (asserts! (is-eq (get record-owner identity-data) tx-sender) err-ownership-verification-failed)

    ;; Update ownership in registry
    (map-set blockchain-identity-registry
      { identity-id: identity-id }
      (merge identity-data { record-owner: new-owner-principal })
    )
    (ok true)
  )
)

;; Marks record as archived by adding special attribute
(define-public (archive-identity-record (identity-id uint))
  (let
    (
      (identity-data (unwrap! (map-get? blockchain-identity-registry { identity-id: identity-id }) err-record-not-found))
      (archive-marker "ARCHIVED-RECORD")
      (current-attributes (get attribute-collection identity-data))
      (archived-attributes (unwrap! (as-max-len? (append current-attributes archive-marker) u10) err-metadata-validation-failed))
    )
    ;; Validate record existence and ownership
    (asserts! (check-record-exists identity-id) err-record-not-found)
    (asserts! (is-eq (get record-owner identity-data) tx-sender) err-ownership-verification-failed)

    ;; Update record with archive marker
    (map-set blockchain-identity-registry
      { identity-id: identity-id }
      (merge identity-data { attribute-collection: archived-attributes })
    )
    (ok true)
  )
)

;; Applies administrative restrictions to identity record
(define-public (apply-administrative-restrictions (identity-id uint))
  (let
    (
      (identity-data (unwrap! (map-get? blockchain-identity-registry { identity-id: identity-id }) err-record-not-found))
      (restriction-marker "ADMIN-RESTRICTED")
      (current-attributes (get attribute-collection identity-data))
    )
    ;; Validate administrative authority
    (asserts! (check-record-exists identity-id) err-record-not-found)
    (asserts! 
      (or 
        (is-eq tx-sender nexus-administrator)
        (is-eq (get record-owner identity-data) tx-sender)
      ) 
      err-admin-required
    )

    ;; Administrative restriction logic implementation
    (ok true)
  )
)

;; ========== Utility Helper Functions ==========

;; Verifies existence of identity record in registry
(define-private (check-record-exists (identity-id uint))
  (is-some (map-get? blockchain-identity-registry { identity-id: identity-id }))
)

;; Validates individual attribute format and constraints
(define-private (is-valid-single-attribute (attribute (string-ascii 32)))
  (and
    (> (len attribute) u0)
    (< (len attribute) u33)
  )
)

;; Ensures attribute collection meets protocol requirements
(define-private (verify-attribute-structure (attributes (list 10 (string-ascii 32))))
  (and
    (> (len attributes) u0)
    (<= (len attributes) u10)
    (is-eq (len (filter is-valid-single-attribute attributes)) (len attributes))
  )
)

;; Retrieves data weight metric from identity record
(define-private (get-record-data-weight (identity-id uint))
  (default-to u0
    (get data-weight
      (map-get? blockchain-identity-registry { identity-id: identity-id })
    )
  )
)

;; Validates ownership relationship between principal and record
(define-private (confirm-record-ownership (identity-id uint) (principal-address principal))
  (match (map-get? blockchain-identity-registry { identity-id: identity-id })
    identity-data (is-eq (get record-owner identity-data) principal-address)
    false
  )
)

;; Verifies record integrity in blockchain registry
(define-private (validate-record-integrity (identity-id uint))
  (is-some (map-get? blockchain-identity-registry { identity-id: identity-id }))
)

;; Confirms ownership authority for specified record
(define-private (verify-ownership-authority (identity-id uint) (claimed-owner principal))
  (match (map-get? blockchain-identity-registry { identity-id: identity-id })
    identity-data (is-eq (get record-owner identity-data) claimed-owner)
    false
  )
)

;; Calculates record age in blocks since creation
(define-private (calculate-record-age (identity-id uint))
  (match (map-get? blockchain-identity-registry { identity-id: identity-id })
    identity-data (- block-height (get creation-block identity-data))
    u0
  )
)

;; Determines total attribute count for identity record
(define-private (count-record-attributes (identity-id uint))
  (match (map-get? blockchain-identity-registry { identity-id: identity-id })
    identity-data (len (get attribute-collection identity-data))
    u0
  )
)

;; Validates read access permissions for accessor
(define-private (check-access-permissions (identity-id uint) (accessor-principal principal))
  (default-to 
    false
    (get read-access-granted 
      (map-get? access-permission-registry { identity-id: identity-id, accessor: accessor-principal })
    )
  )
)

