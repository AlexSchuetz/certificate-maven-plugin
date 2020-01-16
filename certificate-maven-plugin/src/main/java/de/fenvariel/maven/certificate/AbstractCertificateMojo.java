/*
 * Copyright 2020 Alexander Schütz.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.fenvariel.maven.certificate;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.Parameter;

/**
 * Abstract class that contains fields/methods common to Certificate Mojo classes.
 *
 * @author Alexander Schütz (<a href="mailto:fenvariel@googlemail.com">fenvariel</a>)
 * @author $Author$
 * @version $Revision$
 */
public abstract class AbstractCertificateMojo extends AbstractMojo {

    
    /**
     * Set to {@code true} to disable the plugin.
     *
     * @since 1.0.0
     */
    @Parameter( defaultValue = "false" )
    private boolean skip;
    
    /**
     * Enable verbose mode (in mojo and in keytool command).
     * <p/>
     * See <a href="http://docs.oracle.com/javase/1.5.0/docs/tooldocs/windows/keytool.html#Commands">options</a>.
     */
    @Parameter( defaultValue = "false" )
    private boolean verbose;

    /**
     * @return value of the {@link #skip} flag
     */
    public final boolean isSkip()
    {
        return skip;
    }

    /**
     * @param skip the skip flag value to set.
     */
    public final void setSkip( boolean skip )
    {
        this.skip = skip;
    }

    /**
     * @return value of the {@link #verbose} flag
     */
    public final boolean isVerbose()
    {
        return verbose;
    }

    /**
     * @param verbose the verbose flag value to set.
     */
    public final void setVerbose( boolean verbose )
    {
        this.verbose = verbose;
    }

}
