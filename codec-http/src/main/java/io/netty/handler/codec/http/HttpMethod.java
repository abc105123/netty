/*
 * Copyright 2012 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.netty.handler.codec.http;

import io.netty.util.AsciiString;

import static io.netty.util.internal.ObjectUtil.checkNonEmptyAfterTrim;

/**
 * The request method of HTTP or its derived protocols, such as
 * <a href="https://en.wikipedia.org/wiki/Real_Time_Streaming_Protocol">RTSP</a> and
 * <a href="https://en.wikipedia.org/wiki/Internet_Content_Adaptation_Protocol">ICAP</a>.
 */
public class HttpMethod implements Comparable<HttpMethod> {

    private static final String GET_STRING = "GET";
    private static final String POST_STRING = "POST";

    /**
     * The OPTIONS method represents a request for information about the communication options
     * available on the request/response chain identified by the Request-URI. This method allows
     * the client to determine the options and/or requirements associated with a resource, or the
     * capabilities of a server, without implying a resource action or initiating a resource
     * retrieval.
     */
    public static final HttpMethod OPTIONS = new HttpMethod("OPTIONS");

    /**
     * The GET method means retrieve whatever information (in the form of an entity) is identified
     * by the Request-URI.  If the Request-URI refers to a data-producing process, it is the
     * produced data which shall be returned as the entity in the response and not the source text
     * of the process, unless that text happens to be the output of the process.
     */
    public static final HttpMethod GET = new HttpMethod(GET_STRING);

    /**
     * The HEAD method is identical to GET except that the server MUST NOT return a message-body
     * in the response.
     */
    public static final HttpMethod HEAD = new HttpMethod("HEAD");

    /**
     * The POST method is used to request that the origin server accept the entity enclosed in the
     * request as a new subordinate of the resource identified by the Request-URI in the
     * Request-Line.
     */
    public static final HttpMethod POST = new HttpMethod(POST_STRING);

    /**
     * The PUT method requests that the enclosed entity be stored under the supplied Request-URI.
     */
    public static final HttpMethod PUT = new HttpMethod("PUT");

    /**
     * The PATCH method requests that a set of changes described in the
     * request entity be applied to the resource identified by the Request-URI.
     */
    public static final HttpMethod PATCH = new HttpMethod("PATCH");

    /**
     * The DELETE method requests that the origin server delete the resource identified by the
     * Request-URI.
     */
    public static final HttpMethod DELETE = new HttpMethod("DELETE");

    /**
     * The TRACE method is used to invoke a remote, application-layer loop- back of the request
     * message.
     */
    public static final HttpMethod TRACE = new HttpMethod("TRACE");

    /**
     * This specification reserves the method name CONNECT for use with a proxy that can dynamically
     * switch to being a tunnel
     */
    public static final HttpMethod CONNECT = new HttpMethod("CONNECT");

    /**
     * Returns the {@link HttpMethod} represented by the specified name.
     * If the specified name is a standard HTTP method name, a cached instance
     * will be returned.  Otherwise, a new instance will be returned.
     */
    public static HttpMethod valueOf(String name) {
        switch (name) {
            case "OPTIONS": return HttpMethod.OPTIONS;
            case "GET":     return HttpMethod.GET;
            case "HEAD":    return HttpMethod.HEAD;
            case "POST":    return HttpMethod.POST;
            case "PUT":     return HttpMethod.PUT;
            case "PATCH":   return HttpMethod.PATCH;
            case "DELETE":  return HttpMethod.DELETE;
            case "TRACE":   return HttpMethod.TRACE;
            case "CONNECT": return HttpMethod.CONNECT;
            default:        return new HttpMethod(name);
        }
    }

    private final AsciiString name;

    /**
     * Creates a new HTTP method with the specified name.  You will not need to
     * create a new method unless you are implementing a protocol derived from
     * HTTP, such as
     * <a href="https://en.wikipedia.org/wiki/Real_Time_Streaming_Protocol">RTSP</a> and
     * <a href="https://en.wikipedia.org/wiki/Internet_Content_Adaptation_Protocol">ICAP</a>
     */
    public HttpMethod(String name) {
        name = checkNonEmptyAfterTrim(name, "name");
        int index = HttpUtil.validateToken(name);
        if (index != -1) {
            throw new IllegalArgumentException(
                    "Illegal character in HTTP Method: 0x" + Integer.toHexString(name.charAt(index)));
        }
        this.name = AsciiString.cached(name);
    }

    /**
     * Returns the name of this method.
     */
    public String name() {
        return name.toString();
    }

    /**
     * Returns the name of this method.
     */
    public AsciiString asciiName() {
        return name;
    }

    @Override
    public int hashCode() {
        return name().hashCode();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof HttpMethod)) {
            return false;
        }

        HttpMethod that = (HttpMethod) o;
        return name().equals(that.name());
    }

    @Override
    public String toString() {
        return name.toString();
    }

    @Override
    public int compareTo(HttpMethod o) {
        if (o == this) {
            return 0;
        }
        return name().compareTo(o.name());
    }

}
