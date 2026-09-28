import {Versions} from './types.js';
import type {
    Autoprimary,
    CacheFlushResult,
    Comment,
    ConfigSetting,
    Cryptokey,
    CryptokeyCreateRequest,
    Error,
    Metadata,
    NetworkList,
    NetworkUpdateRequest,
    Record,
    SearchResult,
    Server,
    Statistic,
    TSIGKey,
    Version,
    View,
    ViewList,
    ViewZoneInput,
    Zone,
    ZoneSummary,
    ZoneCreateRequest,
    ZoneUpdateRequest
} from './types.js';

const encodePathSegment = (value: string | number) => encodeURIComponent(String(value));
const stringify = (value: { [key: string]: unknown } = {}) => {
    const params = new URLSearchParams();
    for (const [key, item] of Object.entries(value)) {
        if (item === undefined || item === null) continue;
        params.set(key, String(item));
    }
    return params.toString();
};

/**
 * PowerDNS Authoritative HTTP API client.
 *
 * This client is a thin wrapper around the endpoints documented by PowerDNS and
 * keeps request and response payloads close to the upstream API.
 *
 * @typeParam E - Optional caller-defined metadata stored on the client instance.
 * @see https://doc.powerdns.com/authoritative/http-api/
 */
export class Client<E = any> {
    /**
     * Default PowerDNS server target.
     *
     * PowerDNS commonly exposes the authoritative server as `localhost`. When the
     * caller omits a server id, the client falls back to that value.
     */
    get server() {
        if (!this._config.server) this._config.server = {id: 'localhost'};
        if (!this._config.server?.id) this._config.server.id = 'localhost';
        return this._config.server;
    }

    /**
     * Base URL for API requests without the version suffix.
     */
    get baseUrl() {
        return new URL(this._config.baseUrl);
    }

    /**
     * Configured PowerDNS API version path such as `/api/v1`.
     */
    get version() {
        return this._config.version;
    }

    /**
     * Caller-supplied metadata attached to this client instance.
     */
    get extra() {
        return this._config.extra;
    }

    /**
     * Base PowerDNS webserver URL with a trailing slash.
     *
     * This is used for non-versioned endpoints like `/metrics`.
     */
    get webserverUrl() {
        return new URL(this._config.baseUrl.endsWith('/') ? this._config.baseUrl : `${this._config.baseUrl}/`);
    }

    private get fetch() {
        if (!this._config.fetch) return this._config.fetch = globalThis.fetch;
        return this._config.fetch;
    }

    /**
     * Creates a client for a PowerDNS Authoritative webserver.
     *
     * @param _config - Connection details for the PowerDNS API.
     */
    constructor(
        private readonly _config: {
            baseUrl: string;
            apiKey: string;
            version?: Version | string;
            server?: { id: string };
            extra?: E;
            fetch?: typeof fetch;
            logger?: {
                error?: (error: Error) => void;
            };
        }
    ) {
        this._config.baseUrl = this._config.baseUrl.replace(/\/$/, '');
        this._config.version ??= Versions[0];
    }

    /**
     * Access to `/servers/{server_id}/config`.
     *
     * @see https://doc.powerdns.com/authoritative/http-api/server.html
     */
    readonly config = {
        /**
         * Lists PowerDNS configuration settings for a server.
         *
         * @param server - Optional server override.
         */
        get: async (server: { id: string } = this.server): Promise<ConfigSetting[]> =>
            this.requestJson(`/servers/${encodePathSegment(server.id)}/config`)
    };

    /**
     * Access to `/servers`.
     *
     * @see https://doc.powerdns.com/authoritative/http-api/server.html
     */
    readonly servers = {
        /**
         * Lists available PowerDNS servers.
         */
        list: async (): Promise<Server[]> => this.requestJson('/servers'),
        /**
         * Gets a single PowerDNS server description.
         *
         * @param server - Optional server override.
         */
        get: async (server: { id: string } = this.server): Promise<Server> =>
            this.requestJson(`/servers/${encodePathSegment(server.id)}`)
    };

    /**
     * Access to the webserver `/metrics` endpoint.
     *
     * @see https://doc.powerdns.com/authoritative/http-api/
     */
    readonly metrics = {
        /**
         * Reads Prometheus-style metrics text from the PowerDNS webserver.
         */
        get: async (): Promise<string> => {
            const headers = new Headers();
            headers.set('X-API-Key', this._config.apiKey);
            const response = await this.fetch(new URL('metrics', this.webserverUrl), {headers});
            if (!response.ok) {
                let error: Error;
                try {
                    error = await response.json();
                } catch {
                    error = {error: `HTTP ${response.status} ${response.statusText}`};
                }
                throw error;
            }
            return await response.text();
        }
    };

    /**
     * Access to zone endpoints under `/servers/{server_id}/zones`.
     *
     * @param server - Optional server override for all returned zone helpers.
     * @see https://doc.powerdns.com/authoritative/http-api/zone.html
     */
    readonly zones = (server: { id: string } = this.server) => ({
        /**
         * Lists zones for the selected server.
         *
         * @param options - Optional upstream query filters.
         */
        list: (options: Partial<{ zone: string; dnssec: boolean }> = {}): Promise<ZoneSummary[]> =>
            this.requestJson(`/servers/${encodePathSegment(server.id)}/zones?${stringify(options)}`),
        /**
         * Creates a zone.
         *
         * @param zone - Zone payload sent to PowerDNS.
         * @param options - Optional upstream query flags.
         */
        create: (zone: ZoneCreateRequest, options: Partial<{ rrsets: boolean }> = {}): Promise<Zone> =>
            this.requestJson(`/servers/${encodePathSegment(server.id)}/zones?${stringify(options)}`, {
                method: 'POST',
                body: JSON.stringify(zone)
            }),
        /**
         * Reads a zone by id.
         *
         * @param zone - Zone identifier.
         * @param options - Optional upstream query flags.
         */
        get: (
            zone: { id: string },
            options: Partial<{
                rrsets: boolean;
                rrset_name: string;
                rrset_type: string;
                include_disabled: boolean;
            }> = {}
        ): Promise<Zone> =>
            this.requestJson(
                `/servers/${encodePathSegment(server.id)}/zones/${encodePathSegment(zone.id)}?${stringify(options)}`
            ),
        /**
         * Deletes a zone.
         *
         * @param zone - Zone identifier.
         */
        delete: (zone: Pick<Zone, 'id'>): Promise<void> =>
            this.requestVoid(`/servers/${encodePathSegment(server.id)}/zones/${encodePathSegment(zone.id)}`, {
                method: 'DELETE'
            }),
        /**
         * Creates RRSet mutation helpers for a zone.
         *
         * @param zone - Zone identifier.
         * @param target - RRSet name, type, and optional ttl.
         */
        rrset: (zone: { id: string }, target: { name: string; type: string; ttl?: number }) => ({
            /**
             * Deletes the targeted RRSet from the zone.
             */
            delete: async () => {
                await this.requestVoid(
                    `/servers/${encodePathSegment(server.id)}/zones/${encodePathSegment(zone.id)}`,
                    {
                        method: 'PATCH',
                        body: JSON.stringify({
                            rrsets: [{name: target.name, type: target.type, changetype: 'DELETE'}]
                        })
                    }
                );
            },
            /**
             * Replaces RRSet records and comments.
             *
             * If filter callbacks are supplied, the current RRSet is fetched first and
             * then reduced to the matching items before the replacement request is sent.
             *
             * @param update - Replacement records/comments or filter callbacks.
             */
            update: async (
                update: Partial<{
                    records: Record[] | ((record: Record, index: number, array: Record[]) => boolean);
                    comments:
                        | Comment[]
                        | ((comment: Comment, index: number, array: Comment[]) => boolean);
                }>
            ) => {
                const currentZone = await this.zones(server).get(zone, {
                    rrset_name: target.name,
                    rrset_type: target.type
                });
                const [currentSet] = currentZone.rrsets ?? [];
                const ttl = target.ttl ?? currentSet?.ttl;
                if (ttl === undefined) throw {error: 'RRSet ttl is required when no existing RRSet is found'};
                let records: Record[] = currentSet?.records ?? [];
                let comments: Comment[] | undefined;

                if (Array.isArray(update.records)) records = update.records;
                else if (typeof update.records === 'function')
                    records = (currentSet?.records ?? []).filter(update.records);

                if (Array.isArray(update.comments)) comments = update.comments;
                else if (typeof update.comments === 'function')
                    comments = (currentSet?.comments ?? []).filter(update.comments) || [];

                await this.requestVoid(
                    `/servers/${encodePathSegment(server.id)}/zones/${encodePathSegment(zone.id)}`,
                    {
                        method: 'PATCH',
                        body: JSON.stringify({
                            rrsets: [{...target, ttl, changetype: 'REPLACE', records, comments}]
                        } satisfies Pick<Zone, 'rrsets'>)
                    }
                );
                return {};
            },
            /**
             * Appends records or comments to the targeted RRSet.
             *
             * The current RRSet is fetched first so the resulting request can be sent as
             * a full `REPLACE` patch, matching the PowerDNS API model.
             *
             * @param item - Records or comments to append.
             */
            create: async (
                item: Partial<{
                    record: Record | Record[] | undefined;
                    comments: Comment | Comment[] | undefined;
                }>
            ) => {
                const currentZone = await this.zones(server).get(zone, {
                    rrset_name: target.name,
                    rrset_type: target.type
                });
                const [currentSet] = currentZone.rrsets ?? [];
                const update = {
                    rrsets: [
                        {
                            ...target,
                            ttl: target.ttl ?? currentSet?.ttl,
                            changetype: 'REPLACE',
                            records: currentSet?.records ?? [],
                            comments: currentSet?.comments ?? []
                        }
                    ]
                } satisfies Pick<Zone, 'rrsets'>;
                if (update.rrsets[0].ttl === undefined) {
                    throw {error: 'RRSet ttl is required when no existing RRSet is found'};
                }
                if (item.record) {
                    update.rrsets[0].records.push(...(Array.isArray(item.record) ? item.record : [item.record]));
                }
                if (item.comments) {
                    update.rrsets[0].comments?.push(
                        ...(Array.isArray(item.comments) ? item.comments : [item.comments])
                    );
                }
                await this.requestVoid(
                    `/servers/${encodePathSegment(server.id)}/zones/${encodePathSegment(zone.id)}`,
                    {
                        method: 'PATCH',
                        body: JSON.stringify(update)
                    }
                );
                return {};
            }
        }),
        /**
         * Updates zone metadata using the zone `PUT` endpoint.
         *
         * @param zone - Zone update payload including the zone id.
         */
        update: (zone: ZoneUpdateRequest & Pick<Zone, 'id'>): Promise<void> =>
            this.requestVoid(`/servers/${encodePathSegment(server.id)}/zones/${encodePathSegment(zone.id)}`, {
                method: 'PUT',
                body: JSON.stringify(zone)
            }),
        /**
         * Triggers an AXFR retrieve operation for a secondary zone.
         *
         * @param zone - Zone identifier.
         */
        axfrRetrieve: (zone: { id: string }): Promise<void> =>
            this.requestVoid(
                `/servers/${encodePathSegment(server.id)}/zones/${encodePathSegment(zone.id)}/axfr-retrieve`,
                {method: 'PUT'}
            ),
        /**
         * Sends DNS NOTIFY for a zone.
         *
         * @param zone - Zone identifier.
         */
        notify: (zone: { id: string }): Promise<void> =>
            this.requestVoid(
                `/servers/${encodePathSegment(server.id)}/zones/${encodePathSegment(zone.id)}/notify`,
                {method: 'PUT'}
            ),
        /**
         * Exports a zone in text form.
         *
         * @param zone - Zone identifier.
         */
        export: (zone: { id: string }): Promise<string> =>
            this.requestText(`/servers/${encodePathSegment(server.id)}/zones/${encodePathSegment(zone.id)}/export`),
        /**
         * Rectifies DNSSEC records for a zone.
         *
         * @param zone - Zone identifier.
         */
        rectify: (zone: { id: string }): Promise<string> =>
            this.requestText(
                `/servers/${encodePathSegment(server.id)}/zones/${encodePathSegment(zone.id)}/rectify`,
                {method: 'PUT'}
            )
    });

    /**
     * Access to view endpoints.
     *
     * @see https://doc.powerdns.com/authoritative/http-api/zone.html
     */
    readonly views = {
        list: (server: { id: string } = this.server): Promise<ViewList> =>
            this.requestJson(`/servers/${encodePathSegment(server.id)}/views`),
        get: (view: string, server: { id: string } = this.server): Promise<View> =>
            this.requestJson(`/servers/${encodePathSegment(server.id)}/views/${encodePathSegment(view)}`),
        addZone: (view: string, zone: ViewZoneInput, server: { id: string } = this.server): Promise<void> =>
            this.requestVoid(`/servers/${encodePathSegment(server.id)}/views/${encodePathSegment(view)}`, {
                method: 'POST',
                body: JSON.stringify(zone)
            }),
        removeZone: (view: string, zone: { id: string }, server: { id: string } = this.server): Promise<void> =>
            this.requestVoid(
                `/servers/${encodePathSegment(server.id)}/views/${encodePathSegment(view)}/${encodePathSegment(zone.id)}`,
                {method: 'DELETE'}
            )
    };

    /**
     * Access to network-to-view mapping endpoints.
     *
     * @see https://doc.powerdns.com/authoritative/http-api/zone.html
     */
    readonly networks = {
        list: (server: { id: string } = this.server): Promise<NetworkList> =>
            this.requestJson(`/servers/${encodePathSegment(server.id)}/networks`),
        get: (
            network: { ip: string; prefixlen: string | number },
            server: { id: string } = this.server
        ): Promise<NetworkList> =>
            this.requestJson(
                `/servers/${encodePathSegment(server.id)}/networks/${encodePathSegment(network.ip)}/${encodePathSegment(network.prefixlen)}`
            ),
        set: (
            network: { ip: string; prefixlen: string | number },
            update: NetworkUpdateRequest,
            server: { id: string } = this.server
        ): Promise<void> =>
            this.requestVoid(
                `/servers/${encodePathSegment(server.id)}/networks/${encodePathSegment(network.ip)}/${encodePathSegment(network.prefixlen)}`,
                {
                    method: 'PUT',
                    body: JSON.stringify(update)
                }
            )
    };

    /**
     * Access to DNSSEC cryptokey endpoints.
     *
     * @see https://doc.powerdns.com/authoritative/http-api/cryptokey.html
     */
    readonly cryptokeys = {
        list: (zone: { id: string }, server: { id: string } = this.server): Promise<Cryptokey[]> =>
            this.requestJson(
                `/servers/${encodePathSegment(server.id)}/zones/${encodePathSegment(zone.id)}/cryptokeys`
            ),
        create: (zone: { id: string }, key: CryptokeyCreateRequest, server: {
            id: string
        } = this.server): Promise<Cryptokey> =>
            this.requestJson(
                `/servers/${encodePathSegment(server.id)}/zones/${encodePathSegment(zone.id)}/cryptokeys`,
                {
                    method: 'POST',
                    body: JSON.stringify(key)
                }
            ),
        get: (zone: { id: string }, key: { id: string }, server: { id: string } = this.server): Promise<Cryptokey> =>
            this.requestJson(
                `/servers/${encodePathSegment(server.id)}/zones/${encodePathSegment(zone.id)}/cryptokeys/${encodePathSegment(key.id)}`
            ),
        update: (
            zone: { id: string },
            key: { id: string } & Pick<Cryptokey, 'active' | 'published'>,
            server: { id: string } = this.server
        ): Promise<void> =>
            this.requestVoid(
                `/servers/${encodePathSegment(server.id)}/zones/${encodePathSegment(zone.id)}/cryptokeys/${encodePathSegment(key.id)}`,
                {
                    method: 'PUT',
                    body: JSON.stringify({active: key.active, published: key.published})
                }
            ),
        delete: (zone: { id: string }, key: { id: string }, server: { id: string } = this.server): Promise<void> =>
            this.requestVoid(
                `/servers/${encodePathSegment(server.id)}/zones/${encodePathSegment(zone.id)}/cryptokeys/${encodePathSegment(key.id)}`,
                {method: 'DELETE'}
            )
    };

    /**
     * Access to zone metadata endpoints.
     *
     * @see https://doc.powerdns.com/authoritative/http-api/metadata.html
     */
    readonly metadata = {
        list: (zone: { id: string }, server: { id: string } = this.server): Promise<Metadata[]> =>
            this.requestJson(
                `/servers/${encodePathSegment(server.id)}/zones/${encodePathSegment(zone.id)}/metadata`
            ),
        create: (
            zone: { id: string },
            metadata: Pick<Metadata, 'kind' | 'metadata'>,
            server: { id: string } = this.server
        ): Promise<void> =>
            this.requestVoid(
                `/servers/${encodePathSegment(server.id)}/zones/${encodePathSegment(zone.id)}/metadata`,
                {
                    method: 'POST',
                    body: JSON.stringify(metadata)
                }
            ),
        get: (zone: { id: string }, metadata: { kind: string }, server: {
            id: string
        } = this.server): Promise<Metadata> =>
            this.requestJson(
                `/servers/${encodePathSegment(server.id)}/zones/${encodePathSegment(zone.id)}/metadata/${encodePathSegment(metadata.kind)}`
            ),
        update: (
            zone: { id: string },
            metadata: Pick<Metadata, 'kind' | 'metadata'>,
            server: { id: string } = this.server
        ): Promise<Metadata> =>
            this.requestJson(
                `/servers/${encodePathSegment(server.id)}/zones/${encodePathSegment(zone.id)}/metadata/${encodePathSegment(metadata.kind)}`,
                {
                    method: 'PUT',
                    body: JSON.stringify(metadata)
                }
            ),
        delete: (zone: { id: string }, metadata: { kind: string }, server: {
            id: string
        } = this.server): Promise<void> =>
            this.requestVoid(
                `/servers/${encodePathSegment(server.id)}/zones/${encodePathSegment(zone.id)}/metadata/${encodePathSegment(metadata.kind)}`,
                {method: 'DELETE'}
            )
    };

    /**
     * Access to TSIG key endpoints.
     *
     * @see https://doc.powerdns.com/authoritative/http-api/tsigkey.html
     */
    readonly tsigkeys = {
        list: (server: { id: string } = this.server): Promise<TSIGKey[]> =>
            this.requestJson(`/servers/${encodePathSegment(server.id)}/tsigkeys`),
        create: (
            key: Pick<TSIGKey, 'name' | 'algorithm'> & { key?: string },
            server: { id: string } = this.server
        ): Promise<TSIGKey> =>
            this.requestJson(`/servers/${encodePathSegment(server.id)}/tsigkeys`, {
                method: 'POST',
                body: JSON.stringify(key)
            }),
        get: (key: { id: string }, server: { id: string } = this.server): Promise<TSIGKey> =>
            this.requestJson(`/servers/${encodePathSegment(server.id)}/tsigkeys/${encodePathSegment(key.id)}`),
        update: (
            key: { id: string } & Partial<Pick<TSIGKey, 'name' | 'key' | 'algorithm'>>,
            server: { id: string } = this.server
        ): Promise<TSIGKey> =>
            this.requestJson(`/servers/${encodePathSegment(server.id)}/tsigkeys/${encodePathSegment(key.id)}`, {
                method: 'PUT',
                body: JSON.stringify({
                    ...(key.name !== undefined ? {name: key.name} : {}),
                    ...(key.key !== undefined ? {key: key.key} : {}),
                    ...(key.algorithm !== undefined ? {algorithm: key.algorithm} : {})
                })
            }),
        delete: (key: { id: string }, server: { id: string } = this.server): Promise<void> =>
            this.requestVoid(`/servers/${encodePathSegment(server.id)}/tsigkeys/${encodePathSegment(key.id)}`, {
                method: 'DELETE'
            })
    };

    /**
     * Access to autoprimary endpoints.
     *
     * @see https://doc.powerdns.com/authoritative/http-api/autoprimary.html
     */
    readonly autoprimaries = {
        list: (server: { id: string } = this.server): Promise<Autoprimary[]> =>
            this.requestJson(`/servers/${encodePathSegment(server.id)}/autoprimaries`),
        create: (autoprimary: Autoprimary, server: { id: string } = this.server): Promise<void> =>
            this.requestVoid(`/servers/${encodePathSegment(server.id)}/autoprimaries`, {
                method: 'POST',
                body: JSON.stringify(autoprimary)
            }),
        delete: (
            autoprimary: Pick<Autoprimary, 'ip' | 'nameserver'>,
            server: { id: string } = this.server
        ): Promise<void> =>
            this.requestVoid(
                `/servers/${encodePathSegment(server.id)}/autoprimaries/${encodePathSegment(autoprimary.ip)}/${encodePathSegment(autoprimary.nameserver)}`,
                {method: 'DELETE'}
            )
    };

    /**
     * Access to the search endpoint.
     *
     * @see https://doc.powerdns.com/authoritative/http-api/search.html
     */
    readonly search = {
        list: (
            query: {
                q: string;
                max?: number;
                object_type?: 'all' | 'zone' | 'record' | 'comment';
            },
            server: { id: string } = this.server
        ): Promise<SearchResult[]> =>
            this.requestJson(`/servers/${encodePathSegment(server.id)}/search-data?${stringify(query)}`)
    };

    /**
     * Access to statistics endpoints.
     *
     * @see https://doc.powerdns.com/authoritative/http-api/statistics.html
     */
    readonly statistics = {
        get: (
            options?: Partial<{ statistic: string; includerings: boolean }>,
            server: { id: string } = this.server
        ): Promise<Statistic[]> =>
            this.requestJson(`/servers/${encodePathSegment(server.id)}/statistics?${stringify(options)}`)
    };

    /**
     * Access to cache maintenance endpoints.
     *
     * @see https://doc.powerdns.com/authoritative/http-api/cache.html
     */
    readonly cache = {
        flush: (options: { domain: string }, server: { id: string } = this.server): Promise<CacheFlushResult> =>
            this.requestJson(`/servers/${encodePathSegment(server.id)}/cache/flush?${stringify(options)}`, {
                method: 'PUT'
            })
    };

    /**
     * Performs a raw HTTP request against the versioned PowerDNS API.
     *
     * @param path - Path below the configured API version.
     * @param init - Fetch init with an optional `accept` override.
     * @throws Error payload returned by PowerDNS or a synthesized HTTP error.
     */
    protected async _raw(path: string, init?: RequestInit & { accept?: string }) {
        const url = `${this._config.baseUrl}${this._config.version}${path.startsWith('/') ? path : `/${path}`}`;
        const headers = new Headers(init?.headers);
        headers.set('X-API-Key', this._config.apiKey);
        headers.set('Accept', init?.accept ?? 'application/json');
        if (init?.body) headers.set('Content-Type', 'application/json');

        const {accept: _accept, ...requestInit} = init ?? {};
        const response = await this.fetch(url, {...requestInit, headers});

        if (!response.ok) {
            let error: Error;
            try {
                error = await response.json();
            } catch {
                error = {error: `HTTP ${response.status} ${response.statusText}`};
            }
            this._config.logger?.error?.(error);
            throw error;
        }

        return response;
    }

    /**
     * Performs a request and parses the response as JSON.
     *
     * @param path - Path below the configured API version.
     * @param init - Request options.
     */
    protected async requestJson<R = unknown>(path: string, init?: RequestInit): Promise<R> {
        const response = await this._raw(path, init);
        if (!response.headers.get('content-type')?.includes('application/json')) {
            throw {error: 'API response is not JSON', errors: ['Use _raw() for non-JSON responses']};
        }
        return await response.json();
    }

    /**
     * Performs a request and returns either response text or a JSON payload
     * stringified for convenience when PowerDNS responds with JSON.
     *
     * @param path - Path below the configured API version.
     * @param init - Request options.
     */
    protected async requestText(path: string, init?: RequestInit): Promise<string> {
        const response = await this._raw(path, init);
        if (response.headers.get('content-type')?.includes('application/json')) {
            const payload = await response.json();
            return typeof payload === 'string' ? payload : JSON.stringify(payload);
        }
        return await response.text();
    }

    /**
     * Performs a request where only success or failure matters.
     *
     * @param path - Path below the configured API version.
     * @param init - Request options.
     */
    protected async requestVoid(path: string, init?: RequestInit): Promise<void> {
        await this._raw(path, init);
    }
}
