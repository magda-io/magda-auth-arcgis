import express, { Router } from "express";
import { Authenticator, Profile } from "passport";
import { default as ApiClient } from "@magda/auth-api-client";
import { Strategy as ArcGISStrategy } from "passport-arcgis";
import {
    redirectOnError,
    redirectOnSuccess,
    getAbsoluteUrl,
    createOrGetUserToken,
    AuthPluginConfig
} from "@magda/authentication-plugin-sdk";

declare global {
    namespace Express {
        interface User {
            id: string;
            session?: {
                esriGroups: string[];
                esriUser: string;
                accessToken?: string;
                refreshToken: string;
            };
        }
    }
}
export interface AuthPluginRouterOptions {
    authorizationApi: ApiClient;
    authPluginConfig: AuthPluginConfig;
    passport: Authenticator;
    clientId: string;
    clientSecret: string;
    arcgisInstanceBaseUrl: string;
    externalUrl: string;
    authPluginRedirectUrl: string;
    esriOrgGroup: string;
}

interface StrategyOptions {
    clientID: string;
    clientSecret: string;
    callbackURL: string;
    authorizationURL?: string;
    tokenURL?: string;
    userProfileURL?: string;
}

export default function createAuthPluginRouter(
    options: AuthPluginRouterOptions
): Router {
    const authorizationApi = options.authorizationApi;
    const passport = options.passport;
    const { key: authPluginKey } = options.authPluginConfig;
    const clientId = options.clientId;
    const clientSecret = options.clientSecret;
    const externalUrl = options.externalUrl;
    const loginBaseUrl = `${externalUrl}/auth/login/plugin`;
    const esriOrgGroup = options.esriOrgGroup;
    const resultRedirectionUrl = getAbsoluteUrl(
        options.authPluginRedirectUrl,
        externalUrl
    );
    const callbackURL = getAbsoluteUrl(
        `${loginBaseUrl}/${authPluginKey}/return`,
        externalUrl
    );

    if (!clientId) {
        throw new Error("Required client id can't be empty!");
    }

    if (!clientSecret) {
        throw new Error("Required client secret can't be empty!");
    }

    if (!options.arcgisInstanceBaseUrl) {
        throw new Error("Required arcgisInstanceBaseUrl can't be empty!");
    }

    const strategyOptions: StrategyOptions = {
        clientID: clientId,
        clientSecret: clientSecret,
        callbackURL,
        // Overrides 'https://www.arcgis.com/sharing/oauth2/authorize'
        authorizationURL: `${options.arcgisInstanceBaseUrl}/sharing/rest/oauth2/authorize`,
        tokenURL: `${options.arcgisInstanceBaseUrl}/sharing/rest/oauth2/token`
    };

    const router: express.Router = express.Router();

    passport.use(
        new ArcGISStrategy(strategyOptions, function (
            accessToken: string,
            refreshToken: string,
            profile: Profile,
            cb: (error: any, user?: any, info?: any) => void
        ) {
            // ArcGIS Passport provider incorrect defines email instead of emails
            if ((profile as any).email) {
                profile.emails = profile.emails || [];
                profile.emails.push({ value: (profile as any).email });
            }

            profile.displayName =
                profile.displayName ||
                ((profile as any)._json && (profile as any)._json.thumbnail);

            createOrGetUserToken(authorizationApi, profile, "arcgis")
                .then((userToken) => {
                    const url = `${options.arcgisInstanceBaseUrl}/sharing/rest/community/users/${profile.username}?f=json&token=${accessToken}`;
                    fetch(url, { method: "get" })
                        .then((res) => {
                            return res.json();
                        })
                        .then((jsObj) => {
                            const theGroups: any[] = jsObj["groups"];
                            const groupIds: string[] = theGroups.map(
                                (group) => {
                                    return group["id"];
                                }
                            );

                            const theGroupIds = esriOrgGroup
                                ? groupIds.concat([esriOrgGroup])
                                : groupIds;

                            cb(null, {
                                id: userToken.id,
                                session: {
                                    esriGroups: theGroupIds,
                                    esriUser: profile.username,
                                    accessToken: accessToken,
                                    refreshToken: refreshToken
                                }
                            });
                        })
                        .catch((error) => cb(error));
                })
                .catch((error) => cb(error));
        })
    );

    router.get("/", (req, res, next) => {
        const options: any = {
            state: resultRedirectionUrl
        };
        passport.authenticate("arcgis", options)(req, res, next);
    });

    router.get("/token", async (req, res) => {
        if (!req?.user?.session?.accessToken) {
            res.status(403).send("Not logged in: cannot locate `accessToken`");
            return;
        }

        // Verify that the token is still good
        const baseUrl = options.arcgisInstanceBaseUrl;
        const url = `${baseUrl}/sharing/rest/community/self?f=json&token=${req.user.session.accessToken}`;

        let tokenGood = false;

        try {
            const verifyResponse = await fetch(url, { method: "get" });
            const verifyResponseJson = await verifyResponse.json();
            if (verifyResponseJson.error) {
                throw verifyResponseJson.error;
            }
            tokenGood = true;
        } catch (e) {}

        if (!tokenGood && req.user.session.refreshToken) {
            try {
                const tokenUrl = `${baseUrl}/sharing/rest/oauth2/token?client_id=${clientId}&grant_type=refresh_token&refresh_token=${req.user.session.refreshToken}`;
                const newTokenResponse = await fetch(tokenUrl, {
                    method: "get"
                });
                const newToken = await newTokenResponse.json();
                if (newToken.error) {
                    throw newToken.error;
                }
                req.user.session.accessToken = newToken.access_token;
                if (newToken.refresh_token) {
                    req.user.session.refreshToken = newToken.refresh_token;
                }
                tokenGood = true;
            } catch (e) {}
        }

        if (!tokenGood) {
            // Can't get a token, so force the user to sign in again.
            req.logout();
            res.status(403).send("Not logged in");
        }

        res.send({
            accessToken: req.user.session.accessToken
        });
    });

    router.get(
        "/return",
        (
            req: express.Request,
            res: express.Response,
            next: express.NextFunction
        ) => {
            passport.authenticate("arcgis", {
                failWithError: true
            })(req, res, next);
        },
        (
            req: express.Request,
            res: express.Response,
            next: express.NextFunction
        ) => {
            redirectOnSuccess(resultRedirectionUrl, req, res);
        },
        (
            err: any,
            req: express.Request,
            res: express.Response,
            next: express.NextFunction
        ): any => {
            redirectOnError(err, resultRedirectionUrl, req, res);
        }
    );

    return router;
}
